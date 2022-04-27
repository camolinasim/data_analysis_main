#!/usr/bin/env python3


from PyQt5.QtWidgets import *
from PyQt5 import QtCore
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
import sys
import os
import glob
from tkinter import *
from tkinter.ttk import *
import controller
import shutil
import os.path
from os import path
import pandas as pd
import re
from os.path import exists
import random

# importing askopenfile function
# from class filedialog
from tkinter.filedialog import askopenfilename

from random import randint


class MainWindow(QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.w = None
        loadUi("Title_screen_gui_color.ui", self)
        self.btn_create_project.clicked.connect(self.show_create_window)
        self.btn_open_project.clicked.connect(self.show_open_window)
        self.btn_open_project.clicked.connect(self.show_open_window)
        self.btn_anayze_data.clicked.connect(self.show_data_analysis_window)

    def show_data_analysis_window(self):
        if self.w is None:
            self.w = DataAnalysisWindow()
            self.w.show()

        else:
            self.w.close()  # Close window.
            self.w = None  # Discard reference.

    def show_create_window(self):
        if self.w is None:
            self.w = ProjectCreateWindow()
            self.w.show()

        else:
            self.w.close()  # Close window.
            self.w = None  # Discard reference.

    def show_open_window(self):
        if self.w is None:
            window = Tk()  # create and hide root tinker window
            window.withdraw()
            settings = self.openFile()
            window.destroy()
            self.show_selected_project(settings)
            # self.close()
            self.w = SelectedProjectWindow()
            self.w.generateScenarioList(settings=settings)
            self.w.lbl_project_x.setText("Project: " + settings[0][1])
            self.w.show()

        else:
            self.w.close()
            self.w = None

    def openFile(self):
        settings = []
        filepath = askopenfilename(initialdir="C:\\Users\\Cakow\\PycharmProjects\\Main",
                                   title="Open file okay?",
                                   filetypes=(("text files", "*.txt"),
                                              ("all files", "*.*")))
        file = open(filepath, 'r')
        for line in file:
            print(line.strip().split(":"))
            settings.append(line.strip().split(":"))
        file.close()
        return settings

    def show_selected_project(self, settings):
        print("here we are")
        print(settings)


# to clear analyzer window
def clear_analyzer_window(layout, self):
    while layout.count():
        child = layout.takeAt(0)
        if child.widget():
            child.widget().deleteLater()
    top_label = QLabel(
        " frame.number  _ws.col.Time           ip.src           ip.dst  ip.proto  frame.len                                                                               _ws.col.Info\n")
    top_label.setAlignment(QtCore.Qt.AlignTop)

    self.table_view.layout().addWidget(top_label)


def set_status(self, status, warning_or_success='none'):
    self.status.setText(status)
    self.status.adjustSize()
    if(warning_or_success == 'warning'):
        self.status.setStyleSheet(
            "QLabel { color : red; background-color: transparent; }")
    elif(warning_or_success == 'success'):
        self.status.setStyleSheet(
            "QLabel { color : lightgreen; background-color: transparent; }")
    else:
        return


class DataAnalysisWindow(QWidget):
    def __init__(self):
        super(DataAnalysisWindow, self).__init__()
        loadUi("data_analysis.ui", self)
        self.btn_open_pcap.clicked.connect(self.read_pcap)
        self.btn_merge.clicked.connect(self.merge_pcaps)
        self.filter_bar.setEnabled(False)
        self.btn_merge.setEnabled(False)

    def call_tshark_filter(self):
        filter_argument = self.filter_bar.text()
        show_me_only_what_matters = ' -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e frame.number -e _ws.col.Time -e ip.src -e ip.dst -e ip.proto -e frame.len -e _ws.col.Info'
        tshark_command = 'tshark -r ' + path_of_selected_pcap + \
            ' -Y ' + '\"' + filter_argument + '\"'
        stream = os.popen(tshark_command)
        output = stream.read()

        print("Tshark says: " + output)
        output = output.replace("â†’", "->")
        rows = output.split("\n")

        # clear the window before showing thsark's answer.
        clear_analyzer_window(self.table_view.layout(), self)

        ########## POPULATING GUI WITH TSHARK'S ANSWER TO FILTER ###########
        for row in rows:
            packet_row = QLabel(row)
            try:
                packet_name = re.search(r'\d+', packet_row.text()).group()
                packet_row.setObjectName(packet_name)
                packet_row.setAlignment(QtCore.Qt.AlignTop)
                self.table_view.layout().addWidget(packet_row)
            except AttributeError:
                packet_name = "0"

    def merge_pcaps(self):
        pcap1 = path_of_selected_pcap
        pcap2 = askopenfilename()
        pcap2 = os.path.normpath(pcap2)
        pcap1_name = pcap_name.replace(
            ".pcap", "")
        pcap2_name = (os.path.basename(pcap2)).replace(
            ".pcap", "")

        output_file_path = pcap_folder_location + "\\" + \
            pcap1_name + "_" + pcap2_name + ".pcap"
        print(output_file_path)

        mergecap_arguments = 'mergecap ' + pcap1 + \
            ' ' + pcap2 + ' -w ' + output_file_path
        print("mergecap arguments: " + mergecap_arguments)
        stream = os.popen(mergecap_arguments)
        output = stream.read()

        output_file_name = os.path.basename(output_file_path)
        if(output == ''):
            set_status(
                self, f"{output_file_name} has been created -- to view it, open it through the open pcap button", 'success')
        else:
            set_status("there was an error merging your files")

    def read_pcap(self):
        global path_of_selected_pcap
        global pcap_name
        global pcap_folder_location
        global csv_folder

        # clear the window before opening a new pcap
        set_status(self, 'clearing window')
        clear_analyzer_window(self.table_view.layout(), self)

        ########### SETUP - SAVING PCAP PATHS ###########
        set_status(self, 'Waiting for User\'s  Selection')
        Tk().withdraw()
        path_of_selected_pcap = askopenfilename()
        # correcting path from C:/x/x/x/x.pcap -> C:\\x\\x\\x\\x\ x.pcap
        path_of_selected_pcap = os.path.normpath(path_of_selected_pcap)
        pcap_name = os.path.basename(path_of_selected_pcap)
        self.tab_father.setTabText(
            0, str(os.path.basename(path_of_selected_pcap)))
        path_of_selected_pcap_no_extension = path_of_selected_pcap.replace(
            ".pcap", "")
        pcap_folder_location = path_of_selected_pcap.rsplit('http.pcap', 1)
        pcap_folder_location = pcap_folder_location[0].rsplit('\\', 1)[0]
        csv_folder = pcap_folder_location + "\\csv_files"
        name_of_csv = os.path.basename(
            path_of_selected_pcap_no_extension + '.csv')
        csv = csv_folder + "\\" + name_of_csv
        csv_exists = os.path.exists(csv)

        ########## CALLING TSHARK ON SELECTED PCAP ###########
        set_status(self, 'calling tshark. . . (this may take a while)')
        if not csv_exists:
            thsark_read_pcap = 'tshark -r ' + path_of_selected_pcap + \
                ' -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e frame.number -e _ws.col.Time -e ip.src -e ip.dst -e ip.proto -e frame.len -e _ws.col.Info >' + \
                path_of_selected_pcap_no_extension + '.csv'
            stream = os.popen(thsark_read_pcap)
            output = stream.read()

        ########### CREATING FOLDER FOR CSVs ###########

        set_status(self, 'creating csv folder')

        if not path.exists(csv_folder):
            os.mkdir(csv_folder)

        set_status(self, 'creating dataframe')
        ########## CREATING DATAFRAME FROM CSV ###########
        if (not csv_exists):
            csv_path = path_of_selected_pcap_no_extension + '.csv'
            move_this_pcap = csv_path
            over_here = csv_folder
            shutil.move(move_this_pcap, over_here)

        csv_path = csv_folder + "\\" + name_of_csv
        # print(csv_path)
        df = pd.read_csv(csv_path, engine='python', error_bad_lines=False)
        pcap_content = df.to_string(index=False)
        rows = pcap_content.split("\n")

        set_status(self, 'populating GUI')

        ########## POPULATING GUI WITH EACH ROW OF DATAFRAME  ###########
        for row in rows:
            packet_row = QLabel(row)
            try:
                packet_name = re.search(r'\d+', packet_row.text()).group()
                packet_row.setObjectName(packet_name)
                packet_row.setAlignment(QtCore.Qt.AlignTop)
                print(packet_row.text())
                self.table_view.layout().addWidget(packet_row)
            except AttributeError:
                # I'm not adding the first line of the text because it doesn't contain any packet data
                packet_name = "0"

        set_status(self, "enabling filter bar")
        # once a file is read, enable the filter bar
        self.filter_bar.setEnabled(True)
        self.filter_bar.editingFinished.connect(self.call_tshark_filter)
        set_status(self, '')
        self.btn_merge.setEnabled(True)


class ProjectCreateWindow(QWidget):

    def __init__(self):
        super(ProjectCreateWindow, self).__init__()
        loadUi("project_creation_gui.ui", self)
        self.btn_create_project.clicked.connect(self.createfolder)

    def createfolder(self):
        directory = self.txt_path.toPlainText()
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
                self.createSettings(directory)
        except OSError:
            print('Error creating directory: ' + directory)

    def createSettings(self, directory):

        project_name = self.txt_project_name.toPlainText()
        complete_name = os.path.join(directory + '/', project_name)
        f = open(complete_name + ".txt", "w")


class SelectedProjectWindow(QWidget):

    def __init__(self):
        super(SelectedProjectWindow, self).__init__()
        loadUi("selected_project.ui", self)
        self.btn_return_home.clicked.connect(self.goHome)
        self.btn_run_scn.clicked.connect(self.RUNCORE)
        # self.lw_scn_list.addItem("Test_SU1")
        # QListWidgetItem("Test_SU2", self.lw_scn_list)
        # QListWidgetItem("Test_SU3", self.lw_scn_list)
        # self.lw_scn_list.itemSelectionChanged.connect(self.generateScenarioList)

    def generateScenarioList(self, settings):
        print("create list from scenarios in folder")
        #
        # cwd = os.getcwd()
        # fulName=  cwd+'/test_for_name' +'/ScenarioUnits/' +'*.txt'
        # array = glob.glob(fulName)

        # for x in array:
        #    QListWidgetItem(x, self.lw_scn_list)

        # print(os.listdir('/test_for_name'))

    def goHome(self):
        self.close()

    def RUNCORE(self):
        print("###RUNNING CORE###")
        vm_list = "ubuntu(practicum)"
        controller.start_vm(vm_list)


app = QApplication(sys.argv)
mainWindow = MainWindow()
widget = QtWidgets.QStackedWidget()
widget.addWidget(mainWindow)
widget.setFixedHeight(600)
widget.setFixedWidth(800)
widget.show()
app.exec()
