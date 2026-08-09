ucc-gen build --source package --ta-version=$1

# UCC 6.5.3+ no longer generates appserver/templates/, but guard against older
# UCC versions that still emit base.html/redirect.html there. AppInspect (cloud
# tag) flags any file under appserver/templates/ as a deprecated Mako template.
rm -rf output/ansible_addon_for_splunk/appserver/templates

ucc-gen package --path output/ansible_addon_for_splunk
