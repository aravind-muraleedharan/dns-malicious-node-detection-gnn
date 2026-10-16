# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# evaluate_gcn_checkpoint.py
#
#   Loads the saved graph and a trained GCN checkpoint and reports test accuracy,
#   the confusion matrix and ROC-AUC.
#
# Input       : bigdata, model_checkpoints/checkpoint_bigdata_epoch_1999
# Output      : printed metrics
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import pickle
import torch
import numpy as np
import pandas as pd
import torch_geometric.transforms as T
from data_object_generation import DNS
from torch_geometric.nn import GCNConv
import torch.nn.functional as F
import os
from torch_geometric.loader import DataLoader
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, roc_auc_score, average_precision_score, auc


# Laoding dataset

data = torch.load('bigdata')

print(data.x)

class GCN(torch.nn.Module):
    def __init__(self, hidden_channels):
        super().__init__()
        self.conv1 = GCNConv(data.num_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, data.num_classes)

    def forward(self, x, edge_index):
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = x.relu()
        x = F.dropout(x, training=self.training)
        x = self.conv2(x, edge_index)
        return F.log_softmax(x, dim=1)


model = GCN(hidden_channels=10)
print("here is the model", model)
optimizer = torch.optim.Adam(model.parameters(), lr=0.005, weight_decay=5e-4)

# loading pre_trained weights

model.load_state_dict(torch.load('model_checkpoints/checkpoint_bigdata_epoch_1999'))

model.eval()
pred = model(data.x, data.edge_index).argmax(dim=1)
correct = (pred[data.test_mask] == data.y[data.test_mask]).sum()
acc = int(correct) / int(data.test_mask.sum())
print(f'Accuracy: {acc:.4f}')

# confusion matrix

print(confusion_matrix(data.y[data.test_mask], pred[data.test_mask], normalize =None))
auc = roc_auc_score(data.y[data.test_mask], pred[data.test_mask])
print("here is auc", auc)
