#!/usr/bin/env python3


from ast import arguments
from asyncio import subprocess
from importlib.resources import path
from lib2to3.pytree import Node
from time import sleep
from turtle import update
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget, QDialog, QListWidget, \
    QVBoxLayout, QListWidgetItem
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtGui import QStandardItemModel, QMovie, QIcon, QPixmap
from PyQt5.QtCore import Qt
import sys, os, glob
from tkinter import *
from tkinter.ttk import *
import controller
import config_settings
from os import listdir
from os.path import isfile, join
import subprocess
import xml_template
import network_config
from _thread import *
from datetime import datetime
import string

# importing askopenfile function
# from class filedialog
from tkinter.filedialog import askopenfilename

from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5 import QtCore
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
import sys, os, glob
import controller
import shutil
import os.path
from os import path
import pandas as pd
import re
from re import search

from random import randint


class MainWindow(QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.w = None
        loadUi("Title_screen_gui_color.ui", self)
        self.setFixedHeight(600)
        self.setFixedWidth(800)
        self.btn_create_project.clicked.connect(self.show_create_window)
        self.btn_open_project.clicked.connect(self.show_open_window)
        self.btn_anayze_data.clicked.connect(self.show_analysis)
        pixmap = QPixmap('sds_logo.png')
        self.lbl_logo.setPixmap(pixmap)

    def show_analysis(self):
        self.w = DataAnalysisWindow()
        self.w.show()

    def show_create_window(self):
        self.w = ProjectCreateWindow()
        self.w.show()

    def show_open_window(self):
        window = Tk()  # create and hide root tinker window
        window.withdraw()
        settings = self.openFile()
        window.destroy()
        self.show_selected_project(settings)
        ##self.close()
        self.w = SelectedProjectWindow(settings)
        # self.w.generateScenarioList(settings=settings)
        self.w.lbl_project_x.setText("Project: " + settings[0][1])
        self.w.show()

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
    self.listWidget.clear()
    # while layout.count():
    #    child = layout.takeAt(0)
    #    if child.widget():
    #        child.widget().deleteLater()

    top_label = "         #      TimeStamp    source     destin    protocol     frame.len                  Info\n"
    # top_label.setAlignment(QtCore.Qt.AlignTop)
    self.listWidget.addItem(top_label)
    # self.table_view.layout().addWidget(top_label)


def set_status(self, status, warning_or_success='none'):
    self.status.setText(status)
    self.status.adjustSize()
    if (warning_or_success == 'warning'):
        self.status.setStyleSheet(
            "QLabel { color : red; background-color: transparent; }")
    elif (warning_or_success == 'success'):
        self.status.setStyleSheet(
            "QLabel { color : lightgreen; background-color: transparent; }")
    else:
        return

def disable_tabs(self):
    self.tab_father.setTabEnabled(1, False)  # enable/disable the tab
    self.tab_father.setStyleSheet("QTabBar::tab::disabled {width: 0; height: 0; margin: 0; padding: 0; border: none;} ")


class DataAnalysisWindow(QWidget):
    def __init__(self):
        super(DataAnalysisWindow, self).__init__()
        loadUi("data_analysis.ui", self)
        self.btn_open_pcap.clicked.connect(self.read_pcap)
        self.btn_merge.clicked.connect(self.merge_pcaps)
        self.btn_new_pcap.clicked.connect(self.makeNewPcap)
        self.action_bar.setEnabled(False)
        self.btn_merge.setEnabled(False)
        self.movie = QMovie("load-loading.gif")
        self.lbl_movie.setMovie(self.movie)
        # self.movie.start()
        self.lbl_movie.hide()
        self.listWidget.setSelectionMode(2)
        self.pcap_counter = 0
        # set the style sheet
        self.setStyleSheet("QTabBar::tab::disabled {width: 0; height: 0; margin: 0; padding: 0; border: none;} ")
        disable_tabs(self)

    def loadingStart(self):
        self.btn_open_pcap.setDisabled(True)
        self.btn_merge.setDisabled(True)
        self.lbl_movie.show()
        self.movie.start()
        # QtCore.QTimer.singleShot(5000, lambda: self.read_pcap)

        # self.loadingStop()
        print("we waited")

    def test(self):

        self.btn_merge.setDisabled(False)
        print("we waited 2")

    def loadingStop(self):
        self.btn_open_pcap.setDisabled(False)
        self.btn_merge.setDisabled(False)
        self.movie.stop()
        self.lbl_movie.hide()

    def action_call(self):
        action_argument = self.action_bar.text()

        ##REMOVE LOGIC#######
        if search("rm", action_argument):
            print("remove logic")
            index_to_start_reading_from = search(r"\d", action_argument)
            print("index to start reading from: " +
                  str(index_to_start_reading_from.start()))
            print(action_argument[index_to_start_reading_from.start():])
            packets_to_remove = action_argument[index_to_start_reading_from.start(
            ):]

            output_file_path = pcap_folder_location + "\\" + \
                               pcap_name + "_edited.pcap "

            # print(output_file_path)

            editcap_command = 'editcap ' + path_of_selected_pcap + \
                              " " + output_file_path + packets_to_remove

            print("EDIT COMMAND:" + editcap_command)
            stream = os.popen(editcap_command)
            output = stream.read()
            print(output)
        ###FILTER LOGIC###
        else:
            filter_argument = self.action_bar.text()
            show_me_only_what_matters = ' -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e frame.number -e _ws.col.Time -e ip.src -e ip.dst -e ip.proto -e frame.len -e _ws.col.Info'
            tshark_command = 'tshark -r ' + path_of_selected_pcap + \
                             ' -Y ' + '\"' + filter_argument + '\"'
            stream = os.popen(tshark_command)
            output = stream.read()

            print("Tshark says: " + output)
            output = output.replace("â†’", "->")
            rows = output.split("\n")

            # clear the window before showing thsark's answer.
            clear_analyzer_window("self.table_view.layout()", self)

            ########## POPULATING GUI WITH TSHARK'S ANSWER TO FILTER ###########
            for row in range(len(rows)):
                if row != 0:
                    print(rows[row])
                    row2 = rows[row].translate(str.maketrans("", "", string.whitespace))
                    # print(row2)
                    self.listWidget.addItem(rows[row])
                # self.listWidget.addItem(row)
                # packet_row = QLabel(row)
                # try:
                #    packet_name = re.search(r'\d+', packet_row.text()).group()
                #    packet_row.setObjectName(packet_name)
                #    packet_row.setAlignment(QtCore.Qt.AlignTop)
                #    self.table_view.layout().addWidget(packet_row)
                # except AttributeError:
                #    packet_name = "0"

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
        if (output == ''):
            set_status(
                self, f"{output_file_name} has been created -- to view it, open it through the open pcap button",
                'success')
        else:
            set_status("there was an error merging your files")

    def makeNewPcap(self):
        items = self.listWidget.selectedItems()
        pcapstosave = []
        for i in range(len(items)):
            pcapstosave.append(str(self.listWidget.selectedItems()[i].text()))
        print(pcapstosave)

        #############EDIT TO MAKE NEW PCAP FILE################

    def read_pcap(self):
        global path_of_selected_pcap
        global pcap_name
        global pcap_folder_location
        global csv_folder

        self.tab_father.setTabEnabled(self.pcap_counter, True)

        # clear the window before opening a new pcap
        set_status(self, 'clearing window')
        clear_analyzer_window("self.table_view.layout()", self)

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

        self.loadingStart()

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

        for row in range(len(rows)):
            # print(row)
            if row != 0:
                print(rows[row])
                row2 = rows[row].translate(str.maketrans("", "", string.whitespace))
                # print(row2)
                self.listWidget.addItem(rows[row])

        self.pcap_counter = self.pcap_counter + 1
        print(self.pcap_counter)



        set_status(self, "enabling filter bar")
        # once a file is read, enable the filter bar
        self.action_bar.setEnabled(True)
        self.action_bar.editingFinished.connect(self.action_call)
        set_status(self, '')
        self.btn_merge.setEnabled(True)
        self.loadingStop()


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
                directory2 = directory + "/Scenario_units"
                os.makedirs(directory2)
                directory3 = directory + "/pcaps"
                os.makedirs(directory3)
                self.createSettings(directory)
        except OSError:
            print('Error creating directory: ' + directory)

    def createSettings(self, directory):

        project_name = self.txt_project_name.toPlainText()
        parallel_setting = self.txt_parallel.toPlainText()
        path_setting = self.txt_path.toPlainText()
        complete_name = os.path.join(directory + '/', project_name)

        f = open(complete_name + ".txt", "w")
        f.write("Project:" + project_name + "\n")
        f.write("Parallel Run:" + parallel_setting + "\n")
        f.write("Project_path:" + path_setting + "\n")
        f.write("Project:Dummy\n")
        f.close()
        self.close()


class SelectedProjectWindow(QWidget):

    def __init__(self, settings):
        super(SelectedProjectWindow, self).__init__()
        loadUi("selected_project.ui", self)
        self.w = None
        self.path = settings[2][1]
        self.btn_return_home.clicked.connect(self.goHome)
        self.btn_run_scn.clicked.connect(self.test)
        self.btn_run_scn.clicked.connect(self.loadingStart)
        self.btn_create_scn.clicked.connect(self.goCreateScen)
        self.generateScenarioList()
        # self.lw_scn_list.addItem("Test_SU1")
        # QListWidgetItem("Test_SU2", self.lw_scn_list)
        # QListWidgetItem("Test_SU3", self.lw_scn_list)
        self.lw_scn_list.itemDoubleClicked.connect(self.AddScenarioToRunList)
        self.lw_scn_to_run.itemDoubleClicked.connect(self.removeScenario)
        self.btn_refresh.clicked.connect(self.generateScenarioList)
        self.btn_del_selected.clicked.connect(self.deleteScenario)
        self.btn_edit_selected.hide()
        self.movie = QMovie("load-loading.gif")
        self.lbl_movie.setMovie(self.movie)
        # self.movie.start()
        self.lbl_movie.hide()
        self.list = None

    def generateScenarioList(self):
        self.lw_scn_list.clear()
        print("create list from scenarios in folder")
        print(self.path)
        onlyfiles = [f for f in listdir(self.path + '/Scenario_units/') if
                     isfile(join(self.path + '/Scenario_units/', f))]
        print(onlyfiles)
        for X in onlyfiles:
            self.lw_scn_list.addItem(X)

    def deleteScenario(self):
        print("Deleting scenario from scenarios folder")
        if self.lw_scn_list.currentItem():

            file_path = self.path + '/Scenario_units/' + self.lw_scn_list.currentItem().text()

            try:
                os.remove(file_path)
                self.lw_scn_list.clearSelection()
            except OSError as e:
                print("Error: %s : %s" % (file_path, e.strerror))
        else:
            print("No selected file")
            sleep(3)
            self.generateScenarioList()

    def AddScenarioToRunList(self):
        print(self.lw_scn_list.currentItem().text())
        self.lw_scn_to_run.addItem(self.lw_scn_list.currentItem().text())

    def removeScenario(self):
        self.lw_scn_to_run.takeItem(self.lw_scn_to_run.currentRow())

    def loadingStart(self):
        self.btn_create_scn.setDisabled(True)
        self.btn_run_scn.setDisabled(True)
        self.btn_return_home.setDisabled(True)
        self.lbl_movie.show()
        self.movie.start()
        QtCore.QTimer.singleShot(5000, lambda: self.RUNCORE())

        # self.loadingStop()
        print("we waited")

    def test(self):

        self.btn_run_scn.setDisabled(False)
        print("we waited 2")

    def loadingStop(self):
        self.btn_create_scn.setDisabled(False)
        self.btn_run_scn.setDisabled(False)
        self.btn_return_home.setDisabled(False)
        self.movie.stop()
        self.lbl_movie.hide()

    def goHome(self):
        self.close()

    def RUNCORE(self):
        print("###RUNNING CORE###")

        print("##LOADING##")

        output = subprocess.getstatusoutput("vboxmanage list runningvms")
        ub = "ubuntu"
        file_list = [None] * self.lw_scn_to_run.count()
        file_names = [None] * self.lw_scn_to_run.count()

        for x in range(self.lw_scn_to_run.count()):
            file_list[x] = self.path + '/Scenario_units/' + self.lw_scn_to_run.item(x).text()
            file_names[x] = self.lw_scn_to_run.item(x).text()

        if (ub in str(output)):
            print(str(output))
            # pass
        else:
            controller.start_vm("startvm", ub)
            pass

        self.list = file_list
        print(file_list)

        sessionNumbers = []

        for X in range(len(file_list)):
            controller.copy_file("guestcontrol", ub, file_list[X])
            # sleep(15)

            # settings = config_settings.reader(file_list[X])
            # nodes, ips = config_settings.parsing(settings)
            # node, ip = config_settings.convert(nodes, ips)
            # config_settings.configuration(node, ip,file_list[X])
            # configPath = file_list[X].split(".")
            # controller.copy_file("guestcontrol","Ubuntu",configPath[0] + ".ini")
            # sleep(15)

            # controller.pass_command("guestcontrol","Ubuntu")
            print("Passing xml " + file_names[X])
            controller.pass_command("guestcontrol", ub, file_names[X])
            ### ADD COMMAND TO pass xml file###

            # controller.copy_file("guestcontrol","Ubuntu",configPath[0] + ".ini")
            # sleep(15)

            print("passed: " + file_list[X])
            f = open(file_list[X], "r")
            print(f.read())
            f.close()
            sessionNumbers.append(X + 1)

        self.loadingStop()
        self.w = VM_CONTROLLER(ub, file_list, sessionNumbers)

        self.w.show()
        # start_new_thread(function, args)
        # start_new_thread(self.nmap_scan_thread, ())

    def nmap_scan_thread(self):
        ub = "ubuntu"  # MAY NEED UPDATING THIS
        # added just as an example
        print("Starting NMAP scanning")
        controller.core_command("/tmp/pycore.1/node1", "nmap", "10.0.0.1", ub, "output2")
        print("Scanning completed")

    def goCreateScen(self):
        if network_config.subnet_ip:
            network_config.clear()
        self.w = ScenarioCreation(path=self.path)
        self.w.show()


class VM_CONTROLLER(QWidget):

    def __init__(self, vmname, paths, sessionNumbers):

        super(VM_CONTROLLER, self).__init__()
        loadUi("VM_CONTROLLER.ui", self)
        self.ub = vmname
        self.paths = paths
        self.numbers = sessionNumbers
        self.btn_Start_VM.clicked.connect(self.start_vm)
        self.btn_Resume_VM.clicked.connect(self.resume_vm)
        self.btn_Pause_VM.clicked.connect(self.pause_vm)
        self.btn_Stop_VM.clicked.connect(self.stop_vm)
        self.btn_Resume_VM.setDisabled(True)
        self.btn_Start_VM.setDisabled(True)

    def start_vm(self):
        print("#####STARTING VM######")

    def resume_vm(self):
        print("#####RESUMING VM######")
        self.btn_Pause_VM.setDisabled(False)
        self.btn_Resume_VM.setDisabled(True)

        controller.resume_vm("controlvm", self.ub, "resume")

    def pause_vm(self):
        print("#####PAUSING VM######")
        self.btn_Resume_VM.setDisabled(False)
        self.btn_Pause_VM.setDisabled(True)
        controller.pause_vm("controlvm", self.ub, "pause")

    def stop_vm(self):
        print("#####STOPING VM######")
        print(self.numbers)
        for Y in range(len(self.numbers)):
            controller.pass_command3("guestcontrol", self.ub, self.numbers[Y])
        for X in range(len(self.paths)):
            locations = self.paths[X].split("/")
            filenamemodular = locations[2].split(".")
            print(locations)
            print(filenamemodular)
            ###NEED MODULAR PATH FOR USER SPECIFIC
            cwd = os.getcwd()

            print("saving to: " + cwd + locations[0] + "/" + "pcaps")

            controller.pass_command2("guestcontrol", self.ub, filenamemodular[0], cwd + "/" + locations[0] + "/pcaps")
            # controller.extract_file("guestcontrol",self.ub,, filenamemodular) #filenamemodular[0] +".pcap")
        # extract_file("guestcontrol","ubuntu",r"C:/Users/micha/OneDrive/Desktop/PRACTICUM/Main-Production-branch-michael/sprint4/Scenario_units","output1.pcap")

        controller.stop_vm("controlvm", self.ub, "poweroff", "soft")
        self.close()


class LinkCreation(QWidget):

    def __init__(self):
        super(LinkCreation, self).__init__()
        loadUi("Link_Nodes.ui", self)
        self.btn_return.clicked.connect(self.goHome)
        self.btn_create_links.clicked.connect(self.createLinks)

    def createLinks(self):
        node1 = self.txt_fNode_name.toPlainText()
        node2 = self.txt_sNode_name.toPlainText()
        n1IP = self.txt_fn_IP.toPlainText()
        n2IP = self.txt_sn_IP.toPlainText()
        n1MAC = self.txt_fn_MAC.toPlainText()
        n2MAC = self.txt_sn_MAC.toPlainText()
        xml_template.addLink(node1, node2, n1MAC, n2MAC, n1IP, n2IP)
        xml_template.toFile()

    def goHome(self):
        self.close()


class ScenarioCreation(QWidget):

    def __init__(self, path):
        super(ScenarioCreation, self).__init__()
        loadUi("scenario_creation.ui", self)
        self.pathvar = path
        self.pathfile = None
        self.btn_return.clicked.connect(self.goHome)
        self.btn_create_settings.clicked.connect(self.createScenarioFile)
        self.btn_create_nodes.hide()
        self.btn_create_nodes.clicked.connect(self.goCreateNodes)
        self.btn_create_links.hide()
        self.checkBox_services.stateChanged.connect(self.externalServices)
        self.lbl_SDS_IP.hide()
        self.txt_SDS_IP.hide()

        self.lbl_SDS_VM_IP.hide()
        self.txt_SDS_VM_IP.hide()

        self.lbl_CORE_PORT.hide()
        self.txt_CORE_PORT.hide()

        self.lbl_SDS_DOCKER_IP.hide()
        self.txt_SDS_DOCKER_IP.hide()
        # self.btn_create_links.clicked.connect(self.goLinks)

    # def populateFields(self): #TO VIEW (EDIT?) FILE: NOT YET IMPLEMENTED

    #    complete_name = os.path.join(self.pathvar +'/Scenario_units/',self.txt_scen_name.toPlainText())
    #    self.pathfile = complete_name
    #    with open('the-zen-of-python.txt') as f:
    #        line = f.readline()
    #        while line:
    #            line = f.readline()
    #            print(line)

    def externalServices(self):

        if (self.checkBox_services.isChecked()):

            self.lbl_SDS_IP.show()
            self.txt_SDS_IP.show()

            self.lbl_SDS_VM_IP.show()
            self.txt_SDS_VM_IP.show()

            self.lbl_CORE_PORT.show()
            self.txt_CORE_PORT.show()

            self.lbl_SDS_DOCKER_IP.show()
            self.txt_SDS_DOCKER_IP.show()
        else:
            self.lbl_SDS_IP.hide()
            self.txt_SDS_IP.hide()

            self.lbl_SDS_VM_IP.hide()
            self.txt_SDS_VM_IP.hide()

            self.lbl_CORE_PORT.hide()
            self.txt_CORE_PORT.hide()

            self.lbl_SDS_DOCKER_IP.hide()
            self.txt_SDS_DOCKER_IP.hide()

    def goHome(self):
        self.close()

    def createScenarioFile(self):
        complete_name = os.path.join(self.pathvar + '/Scenario_units/', self.txt_scen_name.toPlainText())
        self.pathfile = complete_name
        network_config.createSubnet()
        f = open(complete_name + ".xml", "w")
        # f.write("Scenario_Name:" +self.txt_scen_name.toPlainText() +"\n")
        # f.write("SDS_service:"+ self.txt_SDS_IP.toPlainText() +"\n")
        # f.write("CORE_PORT:"+ self.txt_CORE_PORT.toPlainText() +"\n")
        # f.write("SDS_VM_service:" +self.txt_SDS_VM_IP.toPlainText() +"\n")
        # f.write("SDS_DOCKER_service:"+ self.txt_SDS_DOCKER_IP.toPlainText() +"\n")

        f.close()

        xml_template.setup(complete_name)
        xml_template.toFile()
        self.btn_create_nodes.show()
        # self.btn_create_links.show()

    def goLinks(self):
        # self.txt_scen_name.toPlainText()
        self.w = LinkCreation()
        self.w.show()

    def goCreateNodes(self):
        # self.txt_scen_name.toPlainText()
        self.w = NodeCreation(self.pathfile)
        self.w.show()


class NodeCreation(QWidget):

    def __init__(self, pathfile):
        self.IPcounter = 5
        self.networkCounter = 0
        self.pathfile = pathfile
        super(NodeCreation, self).__init__()
        loadUi("Node_creation_v2.ui", self)
        self.btn_return.clicked.connect(self.goHome)
        self.btn_create_node.clicked.connect(self.appendNode)
        self.btn_add_network.clicked.connect(self.addNetwork)
        # self.btn_create_node.hide()
        self.com_box_node_type.currentTextChanged.connect(self.on_combobox_nodetype_change)
        self.com_box_scanner_bool.currentTextChanged.connect(self.on_combobox_nodetype_change2)
        self.com_box_end_cond.currentTextChanged.connect(self.end_combo_change)
        self.txt_user_login.hide()
        self.txt_password.hide()
        self.com_box_scanner_binary.hide()
        self.txt_Num_iter.hide()
        self.txt_end_cond.hide()
        self.txt_max_parallel.hide()
        self.txt_args.hide()
        self.lbl_user_login.hide()
        self.lbl_password.hide()
        self.lbl_scan_binary.hide()
        self.lbl_Num_iter.hide()
        self.lbl_end_cond.hide()
        self.com_box_end_cond.hide()
        self.lbl_max_parallel.hide()
        self.lbl_args.hide()
        self.listWidget = QtWidgets.QListWidget()
        self.listWidget.setSelectionMode(2)
        # creating checkable combo box

    def addNetwork(self):
        self.networkCounter = self.networkCounter + 1
        self.com_box_network.addItem("Network " + str(self.networkCounter))
        network_config.createSubnet()
        # xml_template.addDevice(self.IPcounter,"routerdevice","router")
        # self.IPcounter = self.IPcounter +1
        xml_template.toFile()

    def end_combo_change(self):
        if (self.com_box_end_cond.currentText() == "Other:"):
            self.txt_end_cond.show()
        elif (self.com_box_end_cond.currentText() == "on-scan-complete"):
            self.txt_end_cond.hide()
            self.txt_end_cond.setPlainText(250)
        else:
            self.txt_end_cond.hide()
            end_cond = self.com_box_network.currentText().split(" ")
            self.txt_end_cond.setPlainText(end_cond[0])

    def on_combobox_nodetype_change2(self):
        if (self.com_box_scanner_bool.currentText() == "True"):
            self.lbl_args.show()
            self.txt_args.show()
            self.com_box_scanner_binary.show()
            self.lbl_scan_binary.show()
            self.com_box_end_cond.show()

            self.txt_Num_iter.show()

            self.txt_max_parallel.show()

            self.lbl_Num_iter.show()
            self.lbl_end_cond.show()
            self.lbl_max_parallel.show()
        else:
            self.lbl_args.hide()
            self.txt_args.hide()
            self.com_box_scanner_binary.hide()
            self.lbl_scan_binary.hide()
            self.com_box_end_cond.hide()

            self.lbl_Num_iter.hide()
            self.lbl_end_cond.hide()
            self.lbl_max_parallel.hide()

            self.txt_Num_iter.hide()
            self.txt_end_cond.hide()
            self.txt_max_parallel.hide()

    def on_combobox_nodetype_change(self):

        if (self.com_box_node_type.currentText() == "NODE"):
            self.txt_user_login.hide()
            self.txt_password.hide()

            self.lbl_user_login.hide()
            self.lbl_password.hide()


        else:
            self.txt_user_login.show()
            self.txt_password.show()

            self.lbl_user_login.show()
            self.lbl_password.show()

    def appendNode(self):

        # f = open(self.pathfile + ".txt","a")

        self.IPcounter = self.IPcounter + 1
        name = self.txt_node_name.toPlainText()
        node_type = self.com_box_node_type.currentText()
        network = self.com_box_network.currentText().split(" ")
        core_type = self.com_box_core_node_type.currentText()
        ##########################
        items = self.lw_services.selectedItems()
        services = ["UserDefined"]
        for i in range(len(items)):
            services.append(str(self.lw_services.selectedItems()[i].text()))

        Log_Traffic = self.com_box_log_traffic.currentText()
        scanner = self.com_box_scanner_binary.currentText()
        scanner_args = self.txt_args.toPlainText().split(",")
        switch_ids = [2,
                      3]  # idea to make a list of switch IDS to keep track of them. also add to this list when a new network/subnet is created
        print(services)
        # ip =
        print(network[1])
        print(self.IPcounter)
        network_config.addIP(self.IPcounter, int(switch_ids[int(network[1])]))
        print(network_config.node_ip)
        print(network_config.getNodeIP(str(self.IPcounter)))
        print(network_config.node_ip.get(str(self.IPcounter)))

        xml_template.addLinkSwitch(self.IPcounter, int(switch_ids[int(network[1])]))

        # f.write(name + "," +  str(self.IPcounter) + "," +  "\n")
        xml_template.addDevice(self.IPcounter, name, core_type, services)

        if (self.com_box_scanner_bool.currentText() == "True"):
            print(self.pathfile)
            now = datetime.now().isoformat()
            now = now.replace(":", "_")
            print(now)
            findscenname = self.pathfile.split("/")
            xml_template.addServiceConfig(str(self.IPcounter),
                                          "touch /home/sds/Documents/pcap/" + str(now) + "_" + findscenname[
                                              2] + "_node_" + name + ".pcap")
            # xml_template.addServiceConfig(str(self.IPcounter),scanner) # THIS may need updating depending on arguments)
            xml_template.addSrvcConfig(str(self.IPcounter),
                                       "sudo chmod 664 /home/sds/Documents/pcap/" + str(now) + "_" + findscenname[
                                           2] + "_node_" + name + ".pcap")
            xml_template.addSrvcConfig(str(self.IPcounter), "tshark -a duration:" + str(
                self.txt_end_cond.toPlainText()) + " -w /home/sds/Documents/pcap/" + str(now) + "_" + findscenname[
                                           2] + "_node_" + name + ".pcap")
            for args in scanner_args:
                xml_template.addSrvcConfig(str(self.IPcounter), scanner + " " + args)
        xml_template.toFile()

        self.lw_list_of_nodes.addItem(name + ": " + network_config.node_ip.get(str(self.IPcounter)))

        # if (self.com_box_node_type.currentText() != "NODE"):
        # f.write("User:"+ self.txt_user_login.toPlainText() +"\n")
        # f.write("Pass:"+ self.txt_password.toPlainText() +"\n")

        # f.write("num_of_iter:"+ self.txt_Num_iter.toPlainText() +"\n")
        # f.write("max_parallel_run:" +self.txt_max_parallel.toPlainText() +"\n")
        # f.write("end_condition:"+ self.txt_end_cond.toPlainText() +"\n")

        # if(self.com_box_scanner_bool.currentText() == "True"):
        # f.write("Scanner:"+ self.com_box_scanner_binary.currentText() +"\n")
        # f.write("arguments:"+ self.txt_args.toPlainText() +"\n")
        # f.close()

        self.txt_node_name.clear()
        self.txt_user_login.clear()
        self.txt_password.clear()
        self.txt_Num_iter.clear()
        self.txt_end_cond.clear()
        self.txt_max_parallel.clear()
        self.txt_args.clear()
        self.com_box_scanner_bool.setCurrentIndex(0)
        self.com_box_end_cond.setCurrentIndex(0)
        self.txt_args.setPlainText("Write commands here, please seperate each command with a ',' (Comma)")
        self.txt_max_parallel.setPlainText("1")
        self.txt_end_cond.setPlainText("1")
        self.txt_Num_iter.setPlainText("1")
        self.txt_user_login.setPlainText("username")

        self.txt_password.setPlainText("password")

    def goHome(self):
        self.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    app.exec()
