# iOS dynamic execution

Based on the master thesis of [Thomas Jirout](https://repositum.tuwien.at/handle/20.500.12708/19197).


## Troubleshooting

### Appium
For correctly setting up Appium, refer to the dedicated Readme section.

In case Appium throws a `Socket hung up` error, this may be normal and after a few retries it usually should work.
Otherwise, check that you have a _working_ version of `WebDriverAgent` installed on your iPhone. Note that if you use a free developer account for compiling `WebDriverAgent`, then the app expires every other day and needs to be deleted. It should be automatically installed when running Appium again, however, if the app is present but unverified, it won't reinstall the app.

Another issue with appium is that it sometimes does not terminate correctly and keeps running after termination (especially after an error).
In that case you can find the pid of the running appium process via
```
sudo lsof -i -P | grep LISTEN | grep :4723
```
and then just kill it.

### rvictl
In case the `rvictl` command does not work properly, i.e. responds with
```
Starting device <UDID> [FAILED]
```
check the following forum post: https://developer.apple.com/forums/thread/655329

For me, the issue was solved by simply running
```
sudo launchctl load -w /Library/Apple/System/Library/LaunchDaemons/com.apple.rpmuxd.plist
```
After that, `rvictl` worked just fine.




### SSH
Guide: https://iphonedev.wiki/SSH_Over_USB

1. `brew install libusbmuxd`
2. Add to `~/.ssh/config`:
```
Host my-iphone
    ProxyCommand inetcat 22 <my-phone-uuid>
    User root
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```
alternative:
``` ssh -oProxyCommand="inetcat 44 <my-phone-uuid>" root@localhost ```
3. Add ssh public key to avoid entering password: default password: `alpine`



### Install Open:
1. Add source to Sileo: `https://apt.thebigboss.org/repofiles/cydia/`
2. Search for `Open` and install
3. `/var/jb/usr/bin/open <appId>` to start app