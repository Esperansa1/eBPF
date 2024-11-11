from itertools import count
import os

import matplotlib.pyplot as plt
import matplotlib as mpl
import mpl_ascii

# Defines the AXES width,height in the terminal
mpl_ascii.AXES_WIDTH=70
mpl_ascii.AXES_HEIGHT=30

mpl.use("module://mpl_ascii")

class Visualizer:
    def __init__(self, delay=1):
        self.delay = delay
        self.reset_visualization()

        # Graph Animation
        self.fig, self.ax = plt.subplots()


    # Reset visualization paramaters
    def reset_visualization(self):
        self.index = count(step=self.delay)
        self.x_values = []
        self.y_values = []


    def visualize_data(self, data):
        # Add new x,y values to graph to plot
        self.x_values.append(next(self.index))
        self.y_values.append(data)
        
        # Clear the terminal
        os.system("cls || clear")
        
        # Plot the graph and show
        plt.plot(self.x_values, self.y_values)
        plt.show()
        plt.cla()
