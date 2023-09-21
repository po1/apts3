import argparse
from dataclasses import dataclass
import datetime
from functools import cache
import hashlib
import io
import logging
import os

import apt.debfile
import apt_pkg  # used as rfc822 parser
import boto3

DEFAULT_COMPONENT = 'main'
DEFAULT_RELEASE = 'stable'

logger = logging.getLogger(__name__)


def multi_hash(file):
    size = 0
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    while True:
        data = file.read(1024 * 1024)
        if not data:
            break
        size += len(data)
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
    return size, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def gets3(bucket, path):
    s3 = boto3.resource('s3')
    obj = s3.Object(bucket, path)
    logger.info(f'Getting s3://{bucket}/{path}')
    try:
        return obj.get()['Body']
    except s3.meta.client.exceptions.NoSuchKey:
        return None


def puts3(bucket, path, data):
    s3 = boto3.resource('s3')
    obj = s3.Object(bucket, path)
    logger.info(f'Putting s3://{bucket}/{path}')
    obj.put(Body=data)


def now():
    _now = datetime.datetime.now(datetime.timezone.utc)
    return _now.strftime('%a, %d %b %Y %H:%M:%S UTC')


def parse_manifest(man):
    while True:
        pkg = []
        while True:
            l = man.readline().rstrip()
            l = l.decode() if isinstance(l, bytes) else l
            if not l:
                break
            pkg.append(l)
        if not pkg:
            break
        yield apt_pkg.TagSection('\n'.join(pkg) + '\n')


class FakeS3Proxy:
    def __init__(self, bucket, prefix):
        self.path = f'{bucket}/{prefix}'
        self.mkdir()

    def mkdir(self):
        path = self.path[:-1] if self.path.endswith('/') else self.path
        logger.info(f'FakeS3: using folder {path}')
        os.makedirs(path, exist_ok=True)

    def get(self, path):
        fullpath = f'{self.path}{path}'
        if not os.path.exists(fullpath):
            logger.info(f'FakeS3: getting {fullpath} [NOT FOUND]')
            return None
        logger.info(f'FakeS3: getting {fullpath}')
        return open(fullpath, 'rb')

    def put(self, path, data):
        fullpath = f'{self.path}{path}'
        logger.info(f'FakeS3: putting {fullpath}')
        filedir = os.path.dirname(fullpath)
        os.makedirs(filedir, exist_ok=True)
        with open(fullpath, 'wb') as file:
            if isinstance(data, bytes):
                file.write(data)
            else:  # assume data is a file-like object
                while (d := data.read(1024 * 1024)):
                    file.write(d)


class S3Proxy:
    def __init__(self, bucket, prefix):
        self.bucket = bucket
        self.prefix = prefix

    def get(self, path):
        return gets3(self.bucket, f'{self.prefix}{path}')

    def put(self, path, data):
        return puts3(self.bucket, f'{self.prefix}{path}', data)


@dataclass
class UnloadedManifest:
    path: str
    size: int
    md5: str
    sha1: str
    sha256: str

    @property
    def arch(self):
        return self.path.split('/')[1].split('-')[1]

    @property
    def component(self):
        # XXX: no slashes in component names. This differs from the spec.
        return self.path.split('/')[0]

    def flush(self):
        return False


class Manifest:
    def __init__(self, s3, codename, component, arch):
        self.s3 = s3
        self.codename = codename
        self.component = component
        self.arch = arch
        self.dirty = False
        self.packages = {}
        self.topush = []
        self.load()

    @staticmethod
    def deb_key(deb):
        return f"{deb['Package']}_{deb['Version']}"

    def deb_filename(self, deb):
        basename = os.path.basename(deb.filename)
        initials = basename[:2]
        return f'pool/{self.component}/{initials}/{basename}'

    @staticmethod
    def deb_hashes(deb):
        with open(deb.filename, 'rb') as file:
            size, md5, sha1, sha256 = multi_hash(file)
        return {
                'Size': size,
                'MD5Sum': md5,
                'SHA1': sha1,
                'SHA256': sha256,
                }

    def load(self):
        data = self.s3.get(self.get_repo_path())
        if data is None:
            return
        self.packages = {self.deb_key(x): x for x in parse_manifest(data)}

    @property
    def path(self):
        return f'{self.component}/binary-{self.arch}/Packages'

    def get_repo_path(self):
        return os.path.join(f'dists/{self.codename}', self.path)

    @property
    def size(self):
        return len(self.flatten())

    @property
    def md5(self):
        return hashlib.md5(self.flatten()).hexdigest()

    @property
    def sha1(self):
        return hashlib.sha1(self.flatten()).hexdigest()

    @property
    def sha256(self):
        return hashlib.sha256(self.flatten()).hexdigest()

    def add_package(self, deb):
        pool_filename = self.deb_filename(deb)
        package = {
                **deb._sections,
                'Filename': pool_filename,
                **self.deb_hashes(deb),
                }
        self.packages[self.deb_key(deb)] =  package
        logger.debug(f' adding {package}')
        self.topush.append((deb.filename, pool_filename))
        self.dirty = True

    def flatten(self):
        lines = []
        for deb in self.packages.values():
            lines += [f'{k}: {v}' for k, v in dict(deb).items()]
            lines.append('')
        return ('\n'.join(lines) + '\n').encode()

    def flush(self):
        if not self.dirty:
            return False

        for localpath, poolpath in self.topush:
            with open(localpath, 'rb') as file:
                self.s3.put(poolpath, file)

        self.s3.put(self.get_repo_path(), self.flatten())
        return True


class Release:
    def __init__(self, s3, codename):
        self.s3 = s3
        self.codename = codename
        self.date = now()
        self.manifests = {}
        self.contents = []
        self.md5 = {}
        self.sha1 = {}
        self.sha256 = {}
        self.load()

    def flatten(self):
        archs = ' '.join(self.architectures)
        comps = ' '.join(self.components)
        lines = [
                f'Codename: {self.codename}',
                f'Date: {self.date}',
                f'Architectures: {archs}',
                f'Components: {comps}',
                f'Suite:',
                ]
# try with sha256 only
#        lines.append('MD5Sum:')
#        lines += [f' {md5} {size:16d} {path}'
#                for path, (md5, size) in self.md5.items()]
#        lines.append('SHA1:')
#        lines += [f' {sha1} {size:16d} {path}'
#                for path, (sha1, size) in self.sha1.items()]
        lines.append('SHA256:')
        lines += [f' {m.sha256} {m.size:16d} {m.path}'
                for m in self.manifests.values()]
        return ('\n'.join(lines) + '\n').encode()

    def load(self):
        def parsehashlist(section):
            hashes = {}
            for line in section.splitlines():
                if not line.strip():
                    continue
                h, s, p = line.split()
                hashes[p] = s, h
            return hashes

        data = self.s3.get(self.path)
        if data is None:
            return
        sections = apt_pkg.TagSection(data.read())
        self.codename = sections['Codename']
        self.date = sections['Date']

#        md5 = parsehashlist(sections['MD5Sum'])
#        sha1 = parsehashlist(sections['SHA1'])
        sha256 = parsehashlist(sections['SHA256'])
        manifests = {}
        for path in sha256:
            size, _sha256 = sha256[path]
#            _, _sha1 = sha1[path]
#            _, _md5 = md5[path]
            manifests[path] = UnloadedManifest(path, int(size), None, None, _sha256)
        self.manifests = manifests

    @property
    def path(self):
        return f'dists/{self.codename}/Release'

    @property
    def architectures(self):
        return set(x.arch for x in self.manifests.values())

    @property
    def components(self):
        return set(x.component for x in self.manifests.values())

    def add_package(self, deb, component=DEFAULT_COMPONENT):
        arch = deb['Architecture']
        if arch == 'all':
            archs = list(self.architectures)
        else:
            archs = [arch]

        for arch in archs:
            key = f'{component}/binary-{arch}/Packages'
            if key not in self.manifests or isinstance(self.manifests[key],
                    UnloadedManifest):
                self.manifests[key] = Manifest(self.s3, self.codename,
                        component, arch)
            self.manifests[key].add_package(deb)

    def flush(self):
        dirty = False
        for _, man in self.manifests.items():
            if man.flush():
                dirty = True

        if dirty:
            self.s3.put(self.path, self.flatten())

    def sign(self, key):
        # TODO: implement
        pass


def upload(debfile, bucket, prefix=None, sign_key=None, codename=None, component=None):
    prefix = prefix or ''
    codename = codename or DEFAULT_RELEASE
    component = component or DEFAULT_COMPONENT

    s3proxy = S3Proxy(bucket, prefix)
    control = apt.debfile.DebPackage(debfile)  # reads the .deb, takes a while
    relfile = Release(s3proxy, codename)
    relfile.add_package(control, component=component)
    relfile.flush()
    if sign_key is not None:
        relfile.sign(sign_key)


def parse_args():
    main_parser = argparse.ArgumentParser(prog='apts3')
    main_parser.add_argument('--verbose', '-v', action='store_true',
            help='more output')
    command_parsers = main_parser.add_subparsers(help='actions', required=True)
    upload_subparser = command_parsers.add_parser('upload',
            help='upload a .deb to the S3-backed APT repo')
    upload_subparser.set_defaults(func=upload)
    upload_subparser.add_argument('--bucket', '-b', required=True,
            help='S3 bucket')
    upload_subparser.add_argument('--prefix', '-p',
            help='s3 prefix path')
    upload_subparser.add_argument('--codename', '-c',
            help='APT codename (e.g. stable)')
    upload_subparser.add_argument('--component', '-m',
            help='APT component (e.g. main)')
    upload_subparser.add_argument('debfile')

    return main_parser.parse_args()


def main():
    args = parse_args()

    verbose = args.__dict__.pop('verbose', False)

    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    func = args.__dict__.pop('func')
    func(**vars(args))
