# Copyright 2014 Open Source Robotics Foundation, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import xml.etree.ElementTree as ElementTree


class NamespaceHelper:
    """Help build namespaces into artifacts."""

    def __init__(self):
        pass


class DDSNamespaceHelper(NamespaceHelper):
    """Help build namespaces into artifacts."""

    def __init__(self):
        pass

    def ros_topic(self, expression, partitions, data_tags, dds_criteria_kind):
        dds_topic = ElementTree.Element('topic')
        dds_topic.text = expression.text.split('/')[-1]

        dds_partition = ElementTree.Element('partition')
        temp =  '/'.join(expression.text.split('/')[:-1])
        dds_partition.text = 'rt' + temp

        if dds_topic.text:
            dds_topics = ElementTree.Element('topics')
            dds_topics.append(dds_topic)
        else:
            dds_topics = None

        if partitions:
            dds_partitions = partitions
        else:
            dds_partitions = ElementTree.Element('partitions')
            dds_partitions.append(dds_partition)

        if data_tags:
            dds_data_tags = data_tags
        else:
            dds_data_tags = None

        return dds_topics, dds_partitions, dds_data_tags

    def ros_service(self, expression, partitions, data_tags, dds_criteria_kind):
        dds_topic = ElementTree.Element('topic')
        dds_topic.text = expression.text.split('/')[-1]

        dds_partition = ElementTree.Element('partition')
        temp =  '/'.join(expression.text.split('/')[:-1])

        if dds_criteria_kind == 'publish':
            dds_partition.text = 'rq' + temp
            dds_topic.text = dds_topic.text + 'Request'
        if dds_criteria_kind == 'subscribe':
            dds_partition.text = 'rr' + temp
            dds_topic.text = dds_topic.text + 'Reply'

        if dds_topic.text:
            dds_topics = ElementTree.Element('topics')
            dds_topics.append(dds_topic)
        else:
            dds_topics = None

        if partitions:
            dds_partitions = partitions
        else:
            dds_partitions = ElementTree.Element('partitions')
            dds_partitions.append(dds_partition)

        if data_tags:
            dds_data_tags = data_tags
        else:
            dds_data_tags = None

        return dds_topics, dds_partitions, dds_data_tags
