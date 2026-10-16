# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# run_processes.py
#
#   Runs generate_features_edges.py as a subprocess.
#
# Input       : -
# Output      : -
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import os
import subprocess

subprocess.run('python3 ' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'generate_features_edges.py'), shell=True)
# subprocess.call('python3 model_training_and_evaluation.py', shell=True)
