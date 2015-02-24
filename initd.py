#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# WARNING This code is still under dev
#
__author__ = 'Adham Helal'

DOCUMENTATION = '''
---

'''

initd_string = '''#!/bin/bash
# export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

NAME="$name"
DESC="$desc"
RUN_AS_USER="$run_user"
RUN_AS_GROUP="$run_group"
BASE_DIR="$base_dir"
GREP_FOR="$grep_for"
EXEC_CMD="$exec_cmd"
EXEC_ARGS="$exec_args"
STOP_CMD="$stop_cmd"
TIMEOUT=$timeout
LOG_FILE=$log_file
WAIT_TILL_TIMEOUT="$wait_till_timeout"
START_METHOD="$start_method"

## Play Specific stuff
IGNORE_PLAY_PID="$ignore_play_pid"

## Flag Variables
START_CODE=0
STOP_CODE=1

# 0 process exist, 1 process does not exist
isRunning() {
    pgrep -f "$GREP_FOR" &> /dev/null
    echo $?
}

GetPid() {
    pgrep -d " " -f "$GREP_FOR"
    echo $!
}

ProcessOk() { echo "[ OK ]" && exit 0; }
ProcessFailed() { echo "[ FAILED ]" && exit 1; }

GetCond(){
    # $1 final call out of time? 0 : no 1: yes
    # $2 failure code? 0 : process should exist 1: process should not exist
    PID_STATUS=$(isRunning)
    if [ $1 -eq 0 ]; then
        if [ $WAIT_TILL_TIMEOUT -eq 1 ]; then
            echo -n "."
        else
            [ $PID_STATUS -eq $2 ] && ProcessOk || echo -n "."
        fi
    else
        [ $PID_STATUS -eq $2 ] && ProcessOk || ProcessFailed
    fi
}

WaitN(){
    count=1;
    until [ $count -ge $TIMEOUT ]
    do
        GetCond 0 "$1"
        sleep 1
        let count=$count+1;
    done
    GetCond 1 "$1"
}

StartDaemon() {
    PID_STATUS=$(isRunning)
    if [ $PID_STATUS -eq $START_CODE ]; then
        PID="$(GetPid)"
        echo "$NAME is already running PID: $PID"
    else
        echo -n  "Starting $NAME "
        [ $IGNORE_PLAY_PID  == 1 ] && rm -f $BASE_DIR/RUNNING_PID
        if [ $START_METHOD == "start-stop-daemon" ]; then
            #Start quite background uid and gid
            start-stop-daemon --start --quiet --background --name $NAME --chdir $BASE_DIR --chuid $RUN_AS_USER --group $RUN_AS_GROUP --startas $EXEC_CMD -- $EXEC_ARGS
        else
            #nohup
            cd $BASE_DIR
            nohup sudo -u $RUN_AS_USER $EXEC_CMD $EXEC_ARGS >> $LOG_FILE 2>&1 &
        fi
        [ $? -ne 0 ] && echo "[ FAILED ]" && exit 1
        WaitN $START_CODE
    fi
}

StopDaemon() {
    PID_STATUS=$(isRunning)
    if [ $PID_STATUS -eq $STOP_CODE ]; then
        echo "$NAME not running."
    else
        PID="$(GetPid)"
        echo -n "Stopping $NAME "
        $STOP_CMD $PID
        [ $? -ne 0 ] && echo "[ FAILED ]" && exit 1
        WaitN $STOP_CODE
    fi
}

statusDaemon() {
    PID_STATUS=$(isRunning)
    if [ $PID_STATUS -eq $START_CODE ]; then
        PID="$(GetPid)"
        echo "$NAME is running with PID:$PID"
    else
        echo "$NAME is not running"
    fi
}
# TODO : graceful-stop
case "$1" in
 start)
        StartDaemon ;;
 stop)
        StopDaemon ;;
 restart)
       StopDaemon
       StartDaemon ;;
 status)
       statusDaemon ;;
*)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1 ;;
esac
exit 0
'''


class DaemonScript(object):
    def __init__(self, module):
        self.module = module
        self.file_sha256 = None
        self.changed = False
        self.msg=""
        if self.module.params["desc"] is None:
            self.module.params["desc"] = self.module.params["name"] + " Daemon"
        if self.module.params["base_dir"] is None:
            self.module.params["base_dir"] = os.path.dirname(self.module.params["path"])
        if self.module.params["grep_for"] is None:
            self.module.params["grep_for"] = self.module.params["exec_cmd"]
        if self.module.params["run_user"] is None:
            self.module.params["run_user"] = getpass.getuser()
        if self.module.params["run_group"] is None:
            self.module.params["run_group"] = getpass.getuser()  # NEEDS fix will break
        if self.module.params["log_file"] is not None and self.module.params["start_method"] == "start-stop-daemon":
            self.module.fail_json(msg="start-stop-daemon does not support logging")

        self.file_args = self.module.load_file_common_arguments(module.params)

    def write_to_dest(self, filename, initd_content):
        try:
            f = open(filename, 'w')
            f.write(initd_content)
            f.close()
        except Exception as E:
            self.module.fail_json(msg="Write error dir name %s does not exist" %
                                      os.path.dirname(self.module.params["path"]))

    def check_dest(self):
        if os.path.isfile(self.module.params["path"]) and not os.access(self.module.params["path"], os.W_OK + os.R_OK):
            self.module.fail_json(msg="Path %s not readable/writable" % (self.module.params["path"]))
        elif os.path.isdir(os.path.dirname(self.module.params["path"])) and \
                not os.access(os.path.dirname(self.module.params["path"]), os.W_OK + os.R_OK):
            self.module.fail_json(msg="Destination directory %s not readable/writable" %
                                      (os.path.dirname(self.module.params["path"])))
        elif not os.path.isdir(os.path.dirname(self.module.params["path"])):
            self.module.fail_json(msg="Destination dir name %s does not exist" %
                                      os.path.dirname(self.module.params["path"]))
        if os.path.isfile(self.module.params["path"]):
            self.file_sha256 = self.module.sha256(self.module.params["path"])

    def main(self):
        self.check_dest()

        initd_template = Template(initd_string)
        initd_script = initd_template.safe_substitute(**self.module.params)
        hash_object = _sha256(initd_script)
        initd_script_dig = hash_object.hexdigest()
        if initd_script_dig == self.file_sha256:
            self.msg = "initd nothing needed"
        else:
            if self.module.check_mode:
                self.changed = True
            else:
                self.write_to_dest(self.module.params["path"], initd_script)
                self.changed = True
                self.msg = "initd update"

        self.changed = self.module.set_fs_attributes_if_different(self.file_args, self.changed)
        self.module.exit_json(changed=self.changed, msg=self.msg)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(default=None, required=True, alias_name="daemon_name"),
            exec_cmd=dict(default=None, required=True),
            path=dict(default=None, required=True),
            desc=dict(default=None, required=False),
            base_dir=dict(default=None, required=False),
            exec_args=dict(default="", required=False),
            state=dict(default="present", choices=["absent", "present"]),
            grep_for=dict(default=None, required=False),
            run_user=dict(default=None, required=False),
            run_group=dict(default=None, required=False),
            stop_cmd=dict(default="kill -9", required=False),
            timeout=dict(default=5, required=False, type="int"),
            wait_till_timeout=dict(default=1, choices=[0, 1], required=False, type="int"),
            log_file=dict(default=None, required=False),
            ignore_play_pid=dict(default=True, choices=BOOLEANS, required=False, type="bool"),
            start_method=dict(default="start-stop-daemon", choices=["start-stop-daemon", "nohup"]),
        ),
        add_file_common_args=True,
        supports_check_mode=True
    )

    DaemonScript(module).main()


from string import Template
import getpass

# import module snippets
from ansible.module_utils.basic import *
main()
