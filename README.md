# Red Hat Event Driven Ansible Add-on For Splunk


## Description
Enhance your **Splunk Enterprise** and **Splunk Cloud Platform** instance by connecting it to the power of **Ansible Automation**.\
This add-on provides a custom alert action that, when triggered, sends critical events from Splunk directly to the Red Hat Ansible Automation Platform (AAP).

Event-Driven Ansible, included in Ansible Automation Platform, enables fast and automated response to Splunk alerts. You choose the alerts to which you would like to respond, and you have the flexibility to design the automated response and logic you would like to take place using Ansible rulebooks.

Desired responses can include:

* Automated notifications
* Service ticket creation
* Fact gathering to expedite service ticket resolution
* Automated remediations such as:
  * Certificate renewals
  * Automated changes to the infrastructure

The add-on utilizes webhooks or Kafka to forward events, both of which are supported by Event-Driven Ansible.

[Splunk and Red Hat collaborate to automate response to observability alerts for improved AIOps](https://www.redhat.com/en/blog/splunk-redhat-collaborate-automate-response-observability-alerts-for-improved-aiops)


## Requirements

### Ansible
* Ansible Automation Platform 2.5 or newer (includes Event-Driven Ansible)
* ansible-core 2.16.0 or newer

### Python
* Python 3.9 or newer on the Splunk search head.

### Python dependencies
The add-on packages the following Python libraries (see `package/lib/requirements.txt`):

* splunktaucclib
* splunk-sdk
* solnlib
* httpx (with http2), httpx-auth, httpcore[asyncio]
* anyio, sniffio, exceptiongroup
* kafka-python (>=2.2.0, <3.0.0)

### Prerequisites
* Install and enable this add-on on a supported Splunk Enterprise or Splunk Cloud Platform deployment
* Configure an Event-Driven Ansible rulebook (with event stream) that listens with a matching webhook or Kafka source before sending alerts from Splunk.
* For ITSI episode actions, Splunk IT Service Intelligence must be installed.
* For adaptive response actions, Splunk Enterprise Security must be installed.

### Compatibility
* Splunk Enterprise 9.4 through 10.4
* Splunk Cloud Platform 10.5
* Ansible Automation Platform >= 2.5


## Installation

### Ansible Automation Platform (AAP) Configurations

All steps below are performed on your AAP instance.

#### 1. Create Projects

Navigate to both:\
`Automation Decisions` → `Projects` → `Create project`\
`Automation Execution` → `Projects` → `Create project`

&emsp; a. Give the project a name and fill in all the required fields.\
&emsp; b. **Source control URL:**
```
https://github.com/ansible/splunk-eda-ta
```
&emsp; c. **Source control branch/tag/commit:** `main`

#### 2. Create Job Template
Navigate to:
`Automation Execution` → `Templates` → `Create template`

&emsp; a. `Name: splunk_eda_ta` - must align with the rulebook `run_job_template` name
```
  action:
    run_job_template:
      name: splunk_eda_ta
```
&emsp; b. With playbook `playbooks/splunk_process_event.yml`

#### 3. Create Credential

Navigate to:
`Automation Decisions` → `Infrastructure` → `Credentials` → `Create credential`

&emsp; a. Give the credential a name.\
&emsp; b. **Credential type:** `Token Event Stream`\
&emsp; c. **Token:** Create a Token - for example `12345678`

#### 4. Create Event Stream

Navigate to:
`Automation Decisions` → `Event Streams` → `Create event stream`

&emsp; a. Give the event stream a name.\
&emsp; b. **Event stream type:** `Token Event Stream`\
&emsp; c. **Credentials:** Use the credential created in [Step 3](#3-create-credential).

> **Important:** After the event stream is created, copy the **URL** from the Event Stream Details page.
> It should look similar to:
>
> `
> https://eco.ansible.aap.gateway:443/eda-event-streams/api/eda/v1/external_event_stream/xxxxxxxx-145a-451e-b8c6-xxxxxxxxxxxx/post/
> `
>
> **Note:** Your Splunk server must have the correct DNS to resolve the AAP gateway FQDN and have the AAP CA certificate installed.

#### 5. Create Rulebook Activation

Navigate to:
`Automation Decisions` → `Rulebook Activations` → `Create rulebook activation`

&emsp; a. Give the rulebook activation a name.\
&emsp; b. **Project:** Choose the project created in [Step 1](#1-create-projects).\
&emsp; c. **Rulebook:** Choose `splunk_webhook_rulebook.yml`.\
&emsp; d. **Event streams:** Choose the event stream created in [Step 4](#4-create-event-stream).

> **Verify:** After the Rulebook Activation is created, check that the Rulebook state is **Running** on the Rulebook Activations page.

- Click on the Rulebook Activation name and go to the **History** tab.
- Click on the running Rulebook Activation instance to view the log.

---

### On the Splunk server

All steps below are performed on your Splunk instance.

#### Install the Red Hat Event-Driven Ansible Add-on for Splunk

In order to configure Webhooks on the Splunk server, you must install the **Red Hat Event-Driven Ansible Add-on for Splunk**.

| Resource   | Link                                            |
| ---------- | ----------------------------------------------- |
| GitHub     | <https://github.com/ansible/splunk-eda-ta>      |
| Splunkbase | <https://splunkbase.splunk.com/app/7868>        |

#### 1. Configure the Webhook

Navigate to:\
`Apps` → `Event Driven Ansible Add-on For Splunk` → `Configuration` → Click **Add**

&emsp; a. Give the Webhook a name.\
&emsp; b. **Integration Type:** `Webhook`\
&emsp; c. **Environment:** Give the environment a name.\
&emsp; d. **Webhook Endpoint:** Use the **URL** created in [AAP Step 4](#4-create-event-stream).\
&emsp; e. **Webhook Auth Type:** `API Key in Header`\
&emsp; f. **Authentication Token:** Use the Token Event Stream created in [AAP Step 3](#3-create-credential) (for example `12345678`).

See the [Automating IT remediation with ITSI and Red Hat Ansible](https://lantern.splunk.com/Data_Descriptors/Red_Hat/Automating_IT_remediation_with_ITSI_and_Red_Hat_Ansible) for end-to-end configuration of webhook, Kafka, saved search alerts, custom commands, ITSI, and Enterprise Security actions.


#### 2. Create an Alert/Episode

Choose one of the following alert actions. For each, select the **Environment** created in [Step 1](#1-configure-the-webhook).

* **Custom Alert Action** — triggered by a saved search in Splunk Core
* **Ansible Adaptive Response Action** — triggered from Splunk Enterprise Security (ES)
* **Ansible Episode Action (ITSI)** — triggered from the Episode Review page in Splunk IT Service Intelligence (ITSI)

For ITSI Episode Action details, see the [Splunk ITSI EDA Rulebook Activation guide](https://github.com/ansible-collections/splunk.itsi/blob/main/extensions/eda/README.md).

### Build
This add-on is built with Splunk's [UCC Generator](https://splunk.github.io/addonfactory-ucc-generator/). Install `ucc-gen` [per the instructions](https://splunk.github.io/addonfactory-ucc-generator/#installation). Building requires a local Python environment (3.9+ recommended); consider using a virtual environment: [Getting Started with UCC](https://splunk.github.io/addonfactory-ucc-generator/quickstart/).

Execute the following from the command line in the root of this repository to build the add-on:

    ucc-gen build --ta-version=<version>

The add-on will be built in an `output` directory in the root of the repository.

### Package

    ucc-gen package --path=./output/ansible_addon_for_splunk

## Use Cases

### Splunk Enterprise — Custom Alert Action

Trigger a custom alert action from a saved search in Splunk Enterprise (Splunk Core). When the search conditions are met, the add-on forwards the alert payload to Ansible Automation Platform over webhook or Kafka. Event-Driven Ansible evaluates the event in a rulebook and can launch playbooks for operational responses such as restarting a service, renewing a certificate, or opening a ticket.

### Splunk Enterprise Security (ES) — Adaptive Response Action

Use the Ansible Adaptive Response Action from Splunk Enterprise Security when a notable event or finding-based detection requires automated response. Analysts can run the action ad hoc from Incident Review (or Mission Control, depending on ES version), or attach it to a detection so critical security events are sent to Event-Driven Ansible for consistent, playbook-driven remediation.

### Splunk IT Service Intelligence (ITSI) — Episode Action

Invoke the Ansible Episode Action from the ITSI Episode Review page, or configure it as part of an ITSI notable events aggregation policy. When an episode is created or updated, episode details are sent to Ansible Automation Platform so Event-Driven Ansible can drive ITOps remediation—reducing MTTR for service-impacting incidents. For ITSI-specific rulebook guidance, see the [Splunk ITSI EDA Rulebook Activation guide](https://github.com/ansible-collections/splunk.itsi/blob/main/extensions/eda/README.md).

### Configuration
Configuration of a service account, depends on the type of connection, and desired authentication method.
Currently webhook supports none, basic, or API key based authentication.
Kafka supports none, SASL plaintext, or with SSL.

Sending one or more events can be done in a variety of ways within Splunk:
* Saved Search Alert Action
* Custom Command
* ITSI Episode Alert Action
* Enterprise Security Adaptive Response Action

## Testing

This add-on was tested against the following environments:

* Splunk Enterprise 9.4 and 10.4
* Splunk Cloud Platform 10.5
* Ansible Automation Platform 2.5, 2.6, and 2.7

## Support

As a Red Hat Ansible Content this Add-on is entitled to [support](https://access.redhat.com/support/) through [Ansible Automation Platform](https://www.redhat.com/en/technologies/management/ansible)

If a support case cannot be opened with Red Hat you can open a GitHub issue on this repo.

## Release Notes and Roadmap

* **Release notes:** [GitHub Releases](https://github.com/ansible/splunk-eda-ta/releases)
* **Published versions:** [Splunkbase — Red Hat Event Driven Ansible Add-on For Splunk](https://splunkbase.splunk.com/app/7868)

## Related Information

* [Automating IT remediation with ITSI and Red Hat Ansible](https://lantern.splunk.com/Data_Descriptors/Red_Hat/Automating_IT_remediation_with_ITSI_and_Red_Hat_Ansible) (Splunk Lantern)
* [Red Hat Event Driven Ansible Add-on For Splunk](https://splunkbase.splunk.com/app/7868) (Splunkbase)
* [Event-Driven Ansible](https://www.redhat.com/en/technologies/management/ansible/event-driven-ansible) (Red Hat product page)
* [Splunk ITSI EDA Rulebook Activation guide](https://github.com/ansible-collections/splunk.itsi/blob/main/extensions/eda/README.md)
* [From Data to Action: Accelerate ITOps with Splunk ITSI and Red Hat Ansible](https://www.splunk.com/en_us/blog/partners/accelerate-itops-with-splunk-itsi-and-red-hat-ansible.html) (Splunk blog)
* [Splunk and Red Hat collaborate to automate response to observability alerts](https://www.redhat.com/en/blog/splunk-redhat-collaborate-automate-response-observability-alerts-for-improved-aiops) (Red Hat blog)

## License Information

This add-on is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html).

A copy of the license is included in the repository and in the downloaded package as `LICENSE`.

