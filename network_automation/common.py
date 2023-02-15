"""
Common functions used in the Project
"""
from .common_dicts import groups_dict
from itertools import chain



def prepare_gui_freeze_boxes(user_groups):
    unfreeze_gui_box = {}
    for k, v in groups_dict.items():
        unfreeze_gui_box[k] = True if (v in user_groups or "admingroup" in user_groups) else False
    return unfreeze_gui_box


def generate_summary(msg):
    summary = "****************************************************************************\n"
    summary += msg
    summary += "****************************************************************************\n\n\n"
    return summary


def get_query_result(query_output, host_ip):
    return (
        query_output.get("plays", {})[0]
        .get("tasks", {})[-1]
        .get("hosts", {})
        .get(host_ip, {})
        .get("ansible_facts", {})
        .get("query_result", {})
    )


def flatten(items):
    return list(chain(*items))
