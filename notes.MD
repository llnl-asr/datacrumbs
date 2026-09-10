# Notes

## Set Cap

```bash
cp $(pwd)/bin/datacrumbs /tmp/ # cannot run cap on nfs. We need file on a file system which supports file attributes.
sudo setcap 'cap_bpf,cap_perfmon+ep' /tmp/datacrumbs 
/tmp/datacrumbs "/home/haridev/datacrumbs/etc/datacrumbs/configs/lead.yaml" "--user" "haridev" "--data_dir" "/home/haridev/datacrumbs/etc/datacrumbs/data" "--trace_log_dir" "/home/haridev/datacrumbs/etc/datacrumbs/logs" "--inclusion_path" "/tmp"
```


```bash
for i in {3..6} {9..11}; do
    sudo scp ./bin/datacrumbs_server_run.sh lead${i}:/etc/flux/system/prolog-job-manager.d/
    sudo scp ./bin/datacrumbs_server_stop.sh lead${i}:/etc/flux/system/epilog.d/
done
```
```bash
for i in {3..6} {9..11}; do
    sudo scp ./etc/datacrumbs/systemd/datacrumbs.service lead${i}:/etc/systemd/system/
done
```
```bash
for i in {2..6} {9..11}; do
echo "Copying prolog and epilog files into server:lead${i}"
sudo ssh lead${i} rm /etc/flux/system/prolog-job-manager.d/datacrumbs*
sudo ssh lead${i} rm /etc/flux/system/epilog.d/datacrumbs*
sudo scp -p ./bin/datacrumbs_service_run.sh lead${i}:/etc/flux/system/prolog-job-manager.d/
sudo scp -p ./bin/datacrumbs_service_stop.sh lead${i}:/etc/flux/system/epilog.d/
sudo scp -p ./etc/datacrumbs/systemd/datacrumbs@.service lead${i}:/etc/systemd/system/
sudo ssh lead${i} << 'EOF'
chmod u+x /etc/flux/system/prolog-job-manager.d/datacrumbs*
chmod u+x /etc/flux/system/epilog.d//datacrumbs*
rm -r /tmp/datacrumbs*
systemctl daemon-reload
EOF
done
```
```bash
for i in 2 {4..6} {9..11}; do
sudo scp -p /etc/flux/system/conf.d/job-manager.toml lead${i}:/etc/flux/system/conf.d/
done
```
```bash
for i in {3..6} {9..11}; do
    sudo ssh lead${i} rm /etc/flux/system/prolog-job-manager.d/datacrumbs_service_run
    sudo ssh lead${i} rm /etc/flux/system/epilog.d/datacrumbs_service_stop
done
```
```bash
for i in 2 {4..6} {9..11}; do
sudo ssh lead${i} << 'EOF'
rm /etc/systemd/system/datacrumbs.service
EOF
done
for i in 2; do
sudo ssh lead${i} << 'EOF'
/admin/scripts/flux_reconfig.sh
flux config reload
EOF
done
```
```bash
for i in {2..6} {9..11}; do
echo Checking lead${i}
sudo ssh lead${i} << 'EOF'
chmod 777 /p/ssd
EOF
done
```

```So the steps are.
Make sure we have epilog and prolog on /etc/flux/system/conf.d/job-manager.toml
restart from broker-0 node of flux if needed
Then install service on every node.
Copy the service scripts into job-manager.d and epilog.d
reload daemon
Then allocate
```


```bash
error_user() {
    ## post exception to flux log, cancel job
    flux job raise --severity=0 ${FLUX_JOB_ID}  "blockfile-prolog: $@"
    ## For convenience of sysadmins, do not drain nodes whenever a user
    ## does something silly that doesn't affect anyone else.
    exit 0
}
warn_user() {
    ## post exception to flux log, cancel job
    flux job raise --severity=1 ${FLUX_JOB_ID}  "datacrumbs-prolog: $@"
    ## For convenience of sysadmins, do not drain nodes whenever a user
    ## does something silly that doesn't affect anyone else.
    exit 0
}
info_user() {
    ## post exception to flux log, cancel job
    flux job raise --severity=7 ${FLUX_JOB_ID}  "blockfile-prolog: $@"
    ## For convenience of sysadmins, do not drain nodes whenever a user
    ## does something silly that doesn't affect anyone else.
    exit 0
}
```

sudo journalctl -u "flux*" --no-pager

```bash
nodes=2
flux run -N $nodes --tasks-per-node 16 ~/software/ior/install/bin/ior -t 1m -b 16m -F -o /tmp/file2
flux run -N $nodes  --tasks-per-node 16 ~/software/ior/install/bin/ior -a MPIIO -t 1m -b 16m -F -o /tmp/file2
flux run -N $nodes --tasks-per-node 16 ~/software/ior/install/bin/ior -c -t 1m -b 16m -F -o /tmp/file2 -z
flux run -N $nodes  --tasks-per-node 16 ~/software/ior/install/bin/ior -t 1m -b 16m -F -o /tmp/file2
```

```bash
mkfs /dev/sda
DIR=/p/ssd
pdsh -g compute mkdir -p $DIR
pdsh -g compute 'mount /dev/sda $DIR'
pdsh -g compute 'chmod 777 $DIR'
```

```bash
for i in {0..16}; do
done
flux run -n 1 ~/software/ior/install/bin/ior -o /p/ssd/test -t 1g -b 64g
flux run -n 16 ~/software/ior/install/bin/ior -o /p/ssd/test -t 32m -b 4g
```
