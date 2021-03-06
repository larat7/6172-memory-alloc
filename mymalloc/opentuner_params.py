#!/usr/bin/env python
#
from opentuner import ConfigurationManipulator
from opentuner.search.manipulator import PowerOfTwoParameter
from opentuner.search.manipulator import IntegerParameter

mdriver_manipulator = ConfigurationManipulator()

"""
See opentuner/search/manipulator.py for more parameter types,
like IntegerParameter, EnumParameter, etc.

TODO(project3): Implement the parameters of your allocator. Once
you have at least one other parameters, feel free to remove ALIGNMENT.
"""
mdriver_manipulator.add_parameter(PowerOfTwoParameter('ALIGNMENT', 8, 8))
mdriver_manipulator.add_parameter(PowerOfTwoParameter('MIN_BLOCK_SIZE', 16, 32768))
mdriver_manipulator.add_parameter(PowerOfTwoParameter('MIN_SPLIT_SIZE', 16, 32768))