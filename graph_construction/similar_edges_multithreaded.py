# ------------------------------------------------------------------------------
# Malicious Node Identification for DNS Data Using Graph Convolutional Networks (ICRAIE 2022)
#
# similar_edges_multithreaded.py
#
#   Earlier multithreaded approach for subdomain similarity edges (Levenshtein
#   distance < 2), comparing every subdomain with all others. Superseded by
#   similar_edges_blocked/ for the full dataset.
#
# Input       : input_files/list_sdoms.csv
# Output      : file.csv           - source, target
#
# Author      : Aravind M
# ------------------------------------------------------------------------------


import threading
import time
import Levenshtein as l
import queue
from random import *
import numpy as np
import tensorflow as tf
# Function for generating similar edges
import sys


fread = open('input_files/list_sdoms.csv', 'r')
all_subdomains = fread.readlines()
list_all_subdomains = []
for line in all_subdomains:
    line = line.replace('\n', '')
    list_all_subdomains.append(line)
fread.close()
print(len(list_all_subdomains))

fwrite_similar = open('file.csv', 'a+')
fwrite_similar.write('source' + ',' + 'target' + '\n')
'''
# Create an empty list
checklist = []
# Iterate over a sequence of numbers from 0 to 4
for i in range(1000):
    # In each iteration, add an empty list to the main list
    checklist.append(list_all_subdomains)
'''
with tf.compat.v1.Session() as sess:
    def similar_edges(subdomain):
        begin = time.time()
        # index = randint(0, 999)
        # list_to_compare_with = checklist[index]
        for line in list_all_subdomains:
            # print(f"creating similar edges for {i}  |  {subdomain}")
            if subdomain != line:
                dist = l.distance(subdomain, line)
                if dist < 2:
                    row1 = subdomain + ',' + line + '\n'
                    # row2 = line + ',' + subdomain + '\n'
                    # if (row1 not in fwrite_similar) and (row2 not in fwrite_similar):
                    outputQueue.put(row1)
                    # if (outputQueue.qsize()) % 100 == 0:
                    #    print("Output Queue size", outputQueue.qsize())
                    # else:
                    #    print("duplicate")
                else:
                    continue
        end = time.time()
        print(f"Total runtime of the program is {end - begin}")

    thread_exit_Flag = 0


    class sample_Thread (threading.Thread):
        def __init__(self, threadID, name, q):
            threading.Thread.__init__(self)
            self.threadID = threadID
            self.name = name
            self.q = q

        def run(self):
            print("initializing " + self.name)
            process_data(self.name, self.q)
            print("Exiting " + self.name)


    # helper function to process data


    def process_data(threadName, q):
        while not thread_exit_Flag:
            queueLock.acquire()
            if not workQueue.empty():
                data = q.get()
                print("The number of elements processed", (4111715-q.qsize()))
                queueLock.release()
                if not outputQueue.empty():
                    data = outputQueue.get()
                    fwrite_similar.write(data)
                    fwrite_similar.flush()
                similar_edges(data)
                # print("% s processing % s" % (threadName, data))
            else:
                queueLock.release()
                time.sleep(0)


    thread_list = []
    for i in range(1000):
        thread_list.append('thread_' + str(i))
    queueLock = threading.Lock()
    workQueue = queue.Queue(4200000)
    outputQueue = queue.Queue(0)
    threads = []
    threadID = 1

    # Create new threads
    for thread_name in thread_list:
        thread = sample_Thread(threadID, thread_name, workQueue)
        thread.start()
        threads.append(thread)
        threadID += 1

    # Fill the queue
    queueLock.acquire()
    for items in list_all_subdomains:
        workQueue.put(items)

    queueLock.release()

    # Wait for the queue to empty
    while not workQueue.empty():
        pass

    # Notify threads it's time to exit
    thread_exit_Flag = 1

    # Wait for all threads to complete
    for t in threads:
        t.join()
    print("Exit Main Thread")
