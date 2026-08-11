Red Hat Event Driven Ansible Add-on For Splunk — Release Notes

Full release history: https://github.com/ansible/splunk-eda-ta/releases

================================================================================
Version 1.1.0
================================================================================

New Features / Bug Fixes / Maintenance

- Removed appserver/templates/ from the distributed package. Splunk Cloud
  Platform 10.4+ deprecates custom Mako templates and AppInspect flags any
  file under appserver/templates/ with check_for_custom_mako_templates. UCC
  6.5.3 no longer generates this directory. The build script explicitly removes
  it to guard against older UCC versions.

- Fixed a Python 3.9 compatibility crash that prevented the alert action from
  sending webhooks on Splunk Enterprise 9.x and 10.x. The h2 library version
  4.4+ uses the Python 3.10 union-type syntax (X | Y) in class definitions,
  which raises a TypeError at import time on Python 3.9. h2 is now pinned to
  <4.4 so a Python-3.9-compatible version is always shipped in the package.
  This also ensures the h2 code directory is overwritten on overlay upgrades,
  since Splunk does not remove old lib/ files when installing a new version.

- Added automatic stale dist-info cleanup in integration_client.py. Splunk
  overlay-installs apps without deleting old files, which causes multiple
  *.dist-info directories to accumulate for the same package across upgrades
  (e.g. h2-4.2.0.dist-info, h2-4.3.0.dist-info, h2-4.4.1.dist-info all
  coexisting). The cleanup runs at import time and removes all but the highest
  version dist-info directory for each managed package.

- Added splunk_kafka_rulebook.yml and splunk_kafka_event.yml as a reference
  rulebook and playbook for receiving Splunk events via Kafka. Event-Driven
  Ansible consumes from a Kafka topic (ansible.eda.kafka source) that Splunk
  publishes to using the | kafkapublish custom search command.

- Updated AppInspect CI to treat future_failure results as blocking failures
  so upcoming cloud compatibility issues are caught before submission.

================================================================================
Version 1.0.3
================================================================================

Bug Fixes

- Added python.required to all Python-backed stanzas to satisfy three AppInspect
  checks that were blocking Splunk Cloud Platform compatibility:
    - check_admin_external_restmap_conf_python_required
    - check_alert_actions_conf_python_required
    - check_commands_conf_python_required
- Added AppInspect environment configuration to CI/CD pipeline.
- Added all missing fields to UCC-replaced generated conf files.

================================================================================
Version 1.0.2
================================================================================

Bug Fixes

- Added Splunk Enterprise 10.2 compatibility.
- Added Python 3.13 support (works with Python 3.13 or system's Python 3).
- Fixed splunkenv.get_splunkd_access_info() call to pass the required
  session_key parameter introduced in newer versions of solnlib.
- Pinned anyio<4.7 to retain Python 3.9 compatibility (anyio 4.6.x was the
  last release to support Python 3.9).
- Set python.version and supportedPythonVersion in app.conf and globalConfig.json
  for explicit Python version declarations.
- Added GitHub Actions CI/CD workflow.
- Added field validation.
- Bumped kafka-python minimum to 2.2.0 for Python 3.13 support.

================================================================================
Version 1.0.1
================================================================================

Initial public release of the Red Hat Event Driven Ansible Add-on For Splunk.
