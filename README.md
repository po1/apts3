Install
-------

Only on debian/ubuntu systems.

```
sudo apt install python3-apt python3-pip
pip install .
```


Uploading a .deb to an S3-backed APT repo
-----------------------------------------

```
apts3 upload --bucket the-s3-bucket the-package.deb
```

By default, the tool uses the `stable` codename and `main` component.
You can then add the repo (assuming it's public) with this sources.list entry:

```
deb [trusted=yes] https://the-s3-bucket.s3.region.amazonaws.com/ stable main
```


You may ask
-----------

### How about signing the repository?

Coming soon.

### Can I remove packages?

No. (coming soon as well).

### How do I make the repo public?

You can use an S3 policy.
Something like the following would do:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Public read",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::the-s3-bucket/*"
        }
    ]
}
```

### Wait, I actually want my repo to be private!

Well then don't use the above policy. In fact, the defaults for new S3 buckets should ensure that your repo is private.

Something like this would probably be useful: https://github.com/zendesk/apt-s3
