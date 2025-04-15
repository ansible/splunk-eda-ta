# Red Hat Event Driven Ansible Add-on for Splunk

## Description
The add-on provides custom alert actions to send Splunk events to Event Driven Ansible.
Currently webhook, and Kafka methods are supported. Works with [generic EDA event source plugins](https://github.com/ansible/event-driven-ansible/blob/main/extensions/eda/plugins/event_source/README.md) for webhook, kafka.

## Documentation

## Build
This add-on is built with Splunk's [UCC Generator](https://github.com/splunk/addonfactory-ucc-generator).  Install `ucc-gen` [per the instructions](https://splunk.github.io/addonfactory-ucc-generator/#installation). Then, execute the following from the command line in the root of this repository to build the add-on:

    ucc-gen build --ta-version=<version>

Example:

    ucc-gen build --ta-version=4.2.0

The add-on will be built in an `output` directory in the root of the repository.

## Package

    ucc-gen package --path=./output/ansible_addon_for_splunk


_____________
    Copyright 2022 Splunk Inc.

    Licensed under the Apache License, Version 2.0 (the "License"); 
    you may not use this file except in compliance with the License. 
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, 
    software distributed under the License is distributed on an "AS IS" BASIS, 
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and limitations under the License.
_____________

## Usage

### Configuration
Configuration of a service account, depends on the type of connection, and desired authentication method.
Currently webhook supports none, basic, or api key based authentication.
Kafka supports none, SASL plaintext, or with SSL.

Sending one or more events can be done in a variety of ways within Splunk:
### Saved Search Alert Action
### Custom Command
### ITSI Episode Alert Action
### Enterprise Security Adaptive Response Action
