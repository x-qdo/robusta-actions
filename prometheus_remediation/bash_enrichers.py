import logging
from typing import List, Any, Dict
from string import Template
from collections import defaultdict

from robusta.api import BashParams, PrometheusKubernetesAlert, BaseBlock, MarkdownBlock, action

class BashTemplateParams(BashParams):
    """
    :var bash_command: Bash command to execute on the target.
    :var template_cmd: If true, the bash command will be templated with the alert labels.

    :example bash_command: ls -l /etc/data/db
    :example bash_command: rabbitmqctl list_consumers -v $vhost | grep $queue
    """

    bash_command: str
    template_cmd: bool = False

def __prepare_bash_command(provided_labels: Dict[Any, Any], bash_command_template: str) -> str:
    labels: Dict[Any, Any] = defaultdict(lambda: "<missing>")
    labels.update(provided_labels)
    template = Template(bash_command_template)
    bash_command = template.safe_substitute(labels)
    return bash_command


@action
def pod_templated_bash_enricher(event: PrometheusKubernetesAlert, params: BashTemplateParams):
    """
    Execute the specified bash command on the target **pod**.
    Enrich the finding with the command results.
    """
    pod = event.get_pod()
    if not pod:
        logging.error(f"cannot run PodBashEnricher on event with no pod: {event}")
        return

    block_list: List[BaseBlock] = []
    if params.template_cmd:
        params.bash_command = __prepare_bash_command(event.alert.labels, params.bash_command)

    exec_result = pod.exec(params.bash_command)
    block_list.append(MarkdownBlock(f"Command results for *{params.bash_command}:*"))
    block_list.append(MarkdownBlock(exec_result))
    event.add_enrichment(block_list)

