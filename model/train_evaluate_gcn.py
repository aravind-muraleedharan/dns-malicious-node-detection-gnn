# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# train_evaluate_gcn.py
#
#   Trains a 2-layer GCN (GCNConv) for malicious / benign node classification on
#   the DNS knowledge graph and evaluates it on the test nodes (accuracy,
#   precision, recall, F1). Optimizer: Adam (lr 5e-3, weight decay 5e-4).
#
# Input       : node_files/, edge_files/ (via data_object_generation.DNS)
# Output      : model_checkpoints/        - model weights every 50 epochs
#               train_epoch_vs_loss.csv   - training loss per epoch
#               run_log.txt               - dataset summary and test metrics
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

os.system('clear')
os.makedirs('model_checkpoints', exist_ok=True)

torch.manual_seed(42)
# data = torch.load('homo_data')

dataset = DNS(root=os.getcwd(), transform=T.Compose([T.NormalizeFeatures(), T.ToUndirected(), T.AddSelfLoops()]))

f1 = open('run_log.txt', 'a+')
f1.write("Here is the Heterodata" + '\n')
f1.write(str(dataset) + '\n')
f1.flush()

# Transformations to data
data = dataset.to_homogeneous()

f1.write(str(data))
f1.flush()

# Defining the GCN class
# taken from https://colab.research.google.com/drive/14OvFnAXggxB8vM4e8vSURUp1TaKnovzX?usp=sharing#scrollTo=fmXWs1dKIzD8


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
        if epoch == 1999:
            xfile = open('probability_values.csv', 'a+')
            print(x.shape)
            for i in range(x.shape[0]):
                xfile.write(str((x[i]).detach().numpy()) + '\n')
        return F.log_softmax(x, dim=1)


model = GCN(hidden_channels=10)
print("here is the model", model)
optimizer = torch.optim.Adam(model.parameters(), lr=0.005, weight_decay=5e-4)

# Training
train_loss_log = open('train_epoch_vs_loss.csv', 'a+')
train_loss_log.write('num_epoch' + ',' + 'loss' + '\n')

model.train()
for epoch in range(2000):
    optimizer.zero_grad()
    out = model(data.x, data.edge_index)
    loss = F.nll_loss(out[data.train_mask], data.y[data.train_mask])

    loss_value = loss.detach().numpy()
    train_loss_log.write(str(epoch) + ',' + str(loss_value) + '\n')
    train_loss_log.flush()
    print(f'Epoch: {epoch:04d}, Loss: {loss:.5f}')
    loss.backward()
    optimizer.step()
    if (epoch % 50 == 0) or (epoch == 1999):
        torch.save(model.state_dict(), 'model_checkpoints/checkpoint_bigdata_epoch_'+str(epoch))

# model_evaluation

model.eval()
pred = model(data.x, data.edge_index).argmax(dim=1)
correct = (pred[data.test_mask] == data.y[data.test_mask]).sum()
acc = int(correct) / int(data.test_mask.sum())
print(f'Accuracy: {acc:.4f}')
f1.write('\n' + "the testing accuracy is" + str(acc))
f1.flush()

# Calculating precision, recall and F1 score

precision = precision_score(data.test_mask, pred)
recall = recall_score(data.test_mask, pred)
f1_scor = f1_score(data.test_mask, pred)
print('Precision is: ', precision_score(data.test_mask, pred))
print('Recall is: ', recall_score(data.test_mask, pred))
print('F1 is: ', f1_score(data.test_mask, pred))

f1.write('\n' + "the precision is" + str(precision))
f1.write('\n' + "the recall is" + str(recall))
f1.write('\n' + "the F1 score is" + str(f1_scor))
f1.flush()

train_loss_log.close()
f1.close()
