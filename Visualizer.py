from itertools import count
import math
import numpy
import os

import matplotlib.pyplot as plt
import matplotlib as mpl
import mpl_ascii

mpl_ascii.AXES_WIDTH=70
mpl_ascii.AXES_HEIGHT=30

mpl.use("module://mpl_ascii")

class Visualizer:
    def __init__(self, delay=1):
        self.delay = delay
        self.reset_visualization()

        # Graph Animation
        self.fig, self.ax = plt.subplots()
        self.ax.legend(title='Packets per second')

    def reset_visualization(self):
        self.index = count(step=self.delay)
        self.x_values = []
        self.y_values = []


    def visualize_network_load(self, total_packets):
        self.x_values.append(next(self.index))
        self.y_values.append(total_packets)
        os.system("clear")
        plt.plot(self.x_values, self.y_values)
        plt.show()
        plt.cla()
    
    def visualize_ip_load(self, data, ip):
        self.x_values.append(next(self.index))
        packet_load = 0
        for packet in data:
            if packet['addr'] == ip:
                packet_load = packet['packets']
        self.y_values.append(packet_load)
        
        os.system("clear")
        plt.plot(self.x_values, self.y_values)
        plt.show()
        plt.cla()