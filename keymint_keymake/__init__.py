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

"""Library for keymaking funtions for keymint buildsystem."""

# set version number
try:
    import pkg_resources
    try:
        __version__ = pkg_resources.require('keymint_keymake')[0].version
    except pkg_resources.DistributionNotFound:
        __version__ = 'unset'
    finally:
        del pkg_resources
except ImportError:
    __version__ = 'unset'
