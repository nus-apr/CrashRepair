#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import sys
from app.utilities import execute_command, error_exit
from app import definitions, values, emitter, reader

CC = "$CREPAIR_CC"
CXX = "$CREPAIR_CXX"
C_FLAGS = "-g -O0  -static -e"
CXX_FLAGS = "-g -O0 -static -e"
LD_FLAGS = "-L/CrashRepair/lib -lcrepair_runtime  -lkleeRuntest"


def config_project(project_path, is_llvm, custom_config_command=None):
    emitter.normal("\t\tconfiguring program")
    dir_command = "cd " + project_path + ";"

    config_command = None
    if custom_config_command is not None:
        if custom_config_command == "skip":
            emitter.warning("\t\t[warning] skipping configuration")
            return
        else:
            if os.path.exists(project_path + "/" + "aclocal.m4"):
                pre_config_command = "rm aclocal.m4;aclocal"
                execute_command(pre_config_command)

            if CC == "wllvm" or CC == "crepair-cc":
                custom_config_command = filter_sanitizers(custom_config_command)
                if "cmake" in custom_config_command:
                    custom_config_command = custom_config_command.replace("clang", "wllvm")
                    custom_config_command = custom_config_command.replace("clang++", "wllvm++")
                # print(custom_config_command)
            # config_command = "CC=" + CC + " "
            # config_command += "CXX=" + CXX + " "
            config_command = custom_config_command
            if "--cc=" in config_command:
                config_command = config_command.replace("--cc=clang-7", "--cc=" + CC)
            # print(config_command)

    elif os.path.exists(project_path + "/autogen.sh"):
        config_command = "./autogen.sh;"
        config_command += "CC=" + CC + " "
        config_command += "CXX=" + CXX + " "
        config_command += "./configure "
        config_command += "CFLAGS=\"" + C_FLAGS + "\" "
        config_command += "CXXFLAGS=\"" + CXX_FLAGS + "\""

    elif os.path.exists(project_path + "/configure.ac"):
        config_command = "autoreconf -i;"
        config_command += "CC=" + CC + " "
        config_command += "CXX=" + CXX + " "
        config_command += "./configure "
        config_command += "CFLAGS=\"" + C_FLAGS + "\" "
        config_command += "CXXFLAGS=\"" + CXX_FLAGS + "\""

    elif os.path.exists(project_path + "/configure.in"):
        config_command = "autoreconf -i;"
        config_command += "CC=" + CC + " "
        config_command += "CXX=" + CXX + " "
        config_command += "./configure "
        config_command += "CFLAGS=\"" + C_FLAGS + "\" "
        config_command += "CXXFLAGS=\"" + CXX_FLAGS + "\""

    elif os.path.exists(project_path + "/configure"):
        config_command = "CC=" + CC + " "
        config_command += "CXX=" + CXX + " "
        config_command += "./configure "
        config_command += "CFLAGS=\"" + C_FLAGS + "\" "
        config_command += "CXXFLAGS=\"" + CXX_FLAGS + "\""

    elif os.path.exists(project_path + "/CMakeLists.txt"):
        config_command = "cmake -DCMAKE_C_COMPILER=" + CC + " "
        config_command += "-DCMAKE_CPP_COMPILER=" + CXX + " "
        config_command += "-DCMAKE_C_FLAGS=\"" + C_FLAGS + "\" "
        config_command += "-DCMAKE_CXX_FLAGS=\"" + CXX_FLAGS + "\" . "

    if is_llvm:
        config_command = "LLVM_COMPILER=clang;" + config_command

    if not config_command:
        error_exit("[Not Found] Configuration Command")

    config_command = dir_command + config_command
    ret_code = execute_command(config_command)
    if int(ret_code) != 0:
        emitter.error(config_command)
        error_exit("CONFIGURATION FAILED!!\nExit Code: " + str(ret_code))


def build_project(project_path, build_command=None):
    emitter.normal("\t\tcompiling program")
    dir_command = "cd " + project_path + ";"
    if build_command is None:
        build_command = "CC=" + CC + " CXX=" + CXX + " "
        if values.CONF_BUILD_FLAGS == "disable":
            build_command += "bear make -j`nproc`  "
        else:
            build_command += "bear make CFLAGS=\"" + C_FLAGS + "\" "
            build_command += "CXXFLAGS=\"" + CXX_FLAGS + " LDFLAGS=" + LD_FLAGS + "\" -j`nproc` > "
    else:
        if build_command == "skip":
            emitter.warning("\t[warning] skipping build")
            return
        if not os.path.isfile(project_path + "/compile_commands.json"):
            build_command = build_command.replace("make ", "bear make ")
            if "-j" not in build_command:
                build_command = build_command + " -j `nproc`"
        build_command = filter_sanitizers(build_command)
    if not build_command:
        error_exit("[Not Found] Build Command")

    build_command = dir_command + build_command
    build_command = build_command + " > " + definitions.FILE_MAKE_LOG
    ret_code = execute_command(build_command)
    if int(ret_code) != 0:
        emitter.error(build_command)
        error_exit("BUILD FAILED!!\nExit Code: " + str(ret_code))
    else:
        if os.path.isfile(project_path + "/compile_commands.json"):
            values.COMPILE_COMMANDS = reader.read_compile_commands(project_path + "/compile_commands.json")


def build_normal():
    global CC, CXX, CXX_FLAGS, C_FLAGS, LD_FLAGS
    emitter.normal("\tbuilding program")
    emitter.normal("\t\tsetting environment variables")
    execute_command("export CREPAIR_CC=" + definitions.DIRECTORY_TOOLS + "/crepair-cc")
    execute_command("export CREPAIR_CXX=" + definitions.DIRECTORY_TOOLS + "/crepair-cxx")

    clean_project(values.CONF_DIR_SRC, values.CONF_PATH_PROGRAM)
    CC = "$CREPAIR_CC"
    CXX = "$CREPAIR_CXX"
    C_FLAGS = "-g -O0"
    CXX_FLAGS = "-g -O0"
    config_project(values.CONF_DIR_SRC, False, values.CONF_COMMAND_CONFIG)
    C_FLAGS = ""
    LD_FLAGS = ""
    CXX_FLAGS = C_FLAGS
    if values.CONF_STATIC:
        C_FLAGS += " -static"
        CXX_FLAGS += " -static"
    build_project(values.CONF_DIR_SRC, values.CONF_COMMAND_BUILD)


def filter_sanitizers(build_command):
    sanitize_group = ['address', 'integer-divide-by-zero']
    for group in sanitize_group:
        build_command = str(build_command).replace("-fsanitize=" + str(group), "")
    return build_command


def restore_project(project_path):
    restore_command = "cd " + project_path + ";"
    if os.path.exists(project_path + "/.git"):
        restore_command += "git clean -fd; git reset --hard HEAD"
    elif os.path.exists(project_path + "/.svn"):
        restore_command += "svn revert -R .; svn status --no-ignore | grep '^\?' | sed 's/^\?     //'  | xargs rm -rf"
    elif os.path.exists(project_path + "/.hg"):
        restore_command += "hg update --clean; hg st -un0 | xargs -0 rm"
    else:
        return
    # print(restore_command)
    execute_command(restore_command)


def soft_restore_project(project_path):
    restore_command = "cd " + project_path + ";"
    if os.path.exists(project_path + "/.git"):
        restore_command += "git reset --hard HEAD"
    elif os.path.exists(project_path + "/.svn"):
        restore_command += "svn revert -R .; "
    elif os.path.exists(project_path + "/.hg"):
        restore_command += "hg update --clean"
    else:
        return
    # print(restore_command)
    execute_command(restore_command)


def clean_project(project_path, binary_path):
    emitter.normal("\t\tcleaning files")
    binary_dir_path = "/".join(str(binary_path).split("/")[:-1])

    if values.CONF_COMMAND_BUILD != "skip":
        clean_command = "cd " + project_path
        clean_command += "; make clean"
        clean_command += "; rm compile_commands.json"
        if values.CONF_COMMAND_CONFIG and values.CONF_COMMAND_CONFIG != "skip":
            clean_command += "; rm CMakeCache.txt"
            clean_command += "; rm -rf CMakeFiles"
        execute_command(clean_command)
    clean_residues = "cd " + binary_dir_path + ";" + "rm -rf ./patches/*;" + "rm -rf ./klee*"
    execute_command(clean_residues)
