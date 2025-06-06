#!/usr/bin/env python

import json
import logging
import logging.handlers
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators

from solnlib import conf_manager
import splunk

from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

ADDON_NAME = "ansible_addon_for_splunk"
LOG_PROGRESS_INTERVAL_SECONDS = 2

logging.root.setLevel(logging.INFO)


def setup_logging():
    # Log to index=_internal, source=LOGGING_FILE_NAME
    # https://dev.splunk.com/enterprise/docs/developapps/addsupport/logging/loggingsplunkextensions/
    logger = logging.getLogger()  # root logger
    SPLUNK_HOME = os.environ['SPLUNK_HOME']

    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
    LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
    LOGGING_STANZA_NAME = 'python'
    LOGGING_FILE_NAME = "kafka_publish_command.log"
    BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
    splunk_log_handler = logging.handlers.RotatingFileHandler(
        os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a')
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logger.addHandler(splunk_log_handler)
    splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
    return logger


setup_logging()


@Configuration()
class KafkaPublishCommand(StreamingCommand):
    env_name = Option(
        doc='Stanza name in ansible_addon_for_splunk_environment.conf',
        default=None,
        require=False)

    error_index_name = Option(
        doc='Index to write failed events to. If not specified, failed events will not be written to an index.',
        default=None,
        require=False)

    bootstrap_servers = Option(
        doc='Comma-separated list of bootstrap servers. Overrides environment config if specified.',
        require=False
    )
    sasl_plain_username = Option(
        doc='SASL PLAIN Auth Username. Overrides environment config if specified.',
        require=False
    )

    sasl_plain_password = Option(
        doc='SASL PLAIN Auth Password. Overrides environment config if specified.',
        require=False
    )

    security_protocol = Option(
        doc='Security Protocol. Overrides environment config if specified.',
        require=False,
        validate=validators.Set('PLAINTEXT', 'SASL_PLAINTEXT', 'SASL_SSL')
    )

    topic_name = Option(
        doc='Kafka topic name',
        require=True)

    linger_ms = Option(
        doc='Linger in milliseconds before sending messages to Kafka',
        require=False,
        default=0,
        validate=validators.Integer()
    )
    batch_size = Option(
        doc="""A small batch size will make batching less common and may reduce throughput 
        (a batch size of zero will disable batching entirely).""",
        require=False,
        default=16384,
        validate=validators.Integer()
    )
    timeout = Option(
        name='timeout',
        doc='Timeout for sending a message to Kafka (in seconds)',
        require=False,
        default=None,
        validate=validators.Integer()
    )

    def get_env_config_by_name(self, env_name: str):
        self.logger.info(f"env name: {self.env_name}")
        session_key = vars(self.metadata.searchinfo)['session_key']
        cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ansible_addon_for_splunk_environment"
        )
        environment_conf = cfm.get_conf("ansible_addon_for_splunk_environment")
        all_stanzas = environment_conf.get_all()
        for stanza_name, stanza_content in all_stanzas.items():
            if stanza_content.get("integration_type") == "kafka" and stanza_content.get("environment") == env_name:
                self.logger.info(f"Found Kafka configuration for environment: {env_name}")
                return stanza_content
        raise ValueError(f"No Kafka configuration found for environment: {env_name}")
        
        

    def get_config_value(self, env, key, optional=False):
        env_value = env.get(key)
        cmd_arg = getattr(self, key, None)
        if cmd_arg is not None and env_value is not None:
            self.write_warning(
                f"Using command argument {key}={cmd_arg} instead of environment config {key}={env_value}")

        if cmd_arg is not None:
            return cmd_arg
        elif env_value is not None:
            return env_value
        elif not optional:
            raise ValueError(f"Missing required argument: {key}")

    def get_producer_instance(self) -> KafkaProducer:
        env = {}
        if self.env_name is not None:
            env = self.get_env_config_by_name(self.env_name)

        security_protocol = self.get_config_value(env, "security_protocol")
        producer_args = {
            "bootstrap_servers": self.get_config_value(env, "bootstrap_servers").split(','),
            "security_protocol": security_protocol,
            "sasl_plain_username": self.get_config_value(env, "sasl_plain_username", optional=True),
            "sasl_plain_password": self.get_config_value(env, "sasl_plain_password", optional=True),
            "sasl_mechanism": "PLAIN" if security_protocol in ["SASL_PLAINTEXT", "SASL_SSL"] else None,
            "ssl_check_hostname": False if security_protocol == "SASL_SSL" else None,
            "value_serializer": lambda x: json.dumps(x).encode('utf-8'),
            "batch_size": self.batch_size,
            "linger_ms": self.linger_ms,
        }
        for k, v in producer_args.items():
            if "password" in k:
                continue
            else:
                self.logger.info(f"KafkaProducer args {k}={v}")

        return KafkaProducer(**producer_args)

    def write_to_index(self, records):
        # Write failed records to an error index via oneshot upload to reduce network requests

        if self.error_index_name is None:
            return
        # Write all records to temp file
        import tempfile
        with tempfile.NamedTemporaryFile() as tmp:
            for record in records:
                tmp.write(json.dumps(record).encode('utf-8'))
                tmp.write(b'\n')
            tmp.flush()
            # Upload temp file to Splunk
            self.service.indexes[self.error_index_name].upload(tmp.name)

    def stream(self, records):
        if self.error_index_name is not None and self.error_index_name not in self.service.indexes:
            raise ValueError(f"Index {self.error_index_name} does not exist")

        try:
            producer = self.get_producer_instance()
        except NoBrokersAvailable as e:
            raise RuntimeError("Bootstrap servers may be unreachable or credentials may be incorrect.") from e

        failed_records = []

        def make_error_handler(failed_record):
            def handler(error):
                self.logger.error(f"Error sending record to Kafka: {error}")
                self.logger.error(f"Record: {failed_record}")
                failed_records.append(failed_record)

            return handler

        timestamp_send_start = time.time()
        last_log_time = timestamp_send_start
        records_successfully_sent = 0

        def success_handler(record_metadata):
            nonlocal records_successfully_sent
            nonlocal last_log_time
            records_successfully_sent += 1
            time_elapsed = time.time() - timestamp_send_start
            time_since_last_log = time.time() - last_log_time
            records_per_second = records_successfully_sent / time_elapsed
            if time_since_last_log >= LOG_PROGRESS_INTERVAL_SECONDS:
                self.logger.info(
                    f"Progress: metadata={record_metadata}, {records_successfully_sent} records sent in {time_elapsed:.3f} seconds.")
                self.logger.info(f"Current performance: {records_per_second:.3f} records/second")
                last_log_time = time.time()

        for record in records:
            producer.send(self.topic_name, record).add_errback(make_error_handler(record)).add_callback(success_handler)
            yield record

        producer.flush(timeout=self.timeout)

        if failed_records and self.error_index_name is not None:
            self.write_error(f"Failed to send {len(failed_records)} records to Kafka")
            self.write_to_index(failed_records)


dispatch(KafkaPublishCommand, sys.argv, sys.stdin, sys.stdout, __name__)