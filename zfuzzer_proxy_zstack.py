import string
import matplotlib.pyplot as plt
import subprocess
import time
import lib_zstack_constants as constant
import socket
import os
import sys
from mutation import helpers
import logging
from coverage import Coverage
logging.basicConfig(
    format='[%(name)s] %(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename='mylog/fuzzing.log',
    level=logging.INFO,
    filemode='w')


def convert_hex_str(hex_str):
    """
    Convert received hex string to corresponding format for Z-Stack Execution.

    """
    seed = ""
    if hex_str not in string.printable or hex_str in string.whitespace:
        seed = seed + str(map(ord, hex_str)[0]) + ' '
    else:
        seed = seed + hex_str + ' '
    return seed


def convert_seed(message):
    seed = ""
    for char in message:
        seed += convert_hex_str(char)
    seed = seed.lstrip(' ').rstrip(' ') + '\n'
    seed_file = open(constant.seed_file, 'w')
    seed_file.write(seed)
    seed_file.close()
    return


def execute_zstack(message):
    """
    Execute Z-Stack and record its execution result
    :return: the status of execution.
             If success, it will return 0. Otherwise, it will return status codes between 1 - 9.
             Except there is execution exception, it will return a special message.
    """
    command = [constant.cmd, '/C', constant.zstack_execution]
    output = ""
    status = ""
    try:
        z_result = open(constant.zstack_log_dir+"zstack_result.txt", 'a')
        z_result.write("\n************* {0} *************\nReceived message:{1}"
                       .format(helpers.get_time_stamp(), message))
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        if "ERROR" in e.output:
            call_stack_num = e.output.find("Call Stack:")
            memory_error_num = e.output.find("User error: Memory access error:")
            call_stack = e.output[call_stack_num: memory_error_num]
            status = "Process Failed!\n" + call_stack
        else:
            status = e.returncode
    finally:
        success_pattern = "Test zcl_ProcessMessageMSG:"
        index = output.find(success_pattern)
        if index != -1:
            code = output[index + len(success_pattern):index + len(success_pattern) + 4]
            status = str(int(code, 0))
        elif "ERROR" in output:
            call_stack_num = output.find("Call Stack:")
            memory_error_num = output.find("User error: Memory access error:")
            call_stack = output[call_stack_num:memory_error_num]
            status = "Process Failed!\n" + call_stack
        elif "CSpyBat terminating." in output:
            status = "0"
        else:
            status = "Server Error!\n"
        z_result.write(output)
        z_result.write("\n************* {} *************\n".format(helpers.get_time_stamp()))
        z_result.close()
    return status

# Referred ROM Error message: User error: ERROR: The instruction at 0x002071A4 tried to branch to the aligned (ARM) address 0x00000000. This will cause a HardFault.

cfg_file = 'zcl_cfg.json'
cfg_dir = 'offline_parser\\cfg_files\\'

target_zcl_cfgs = [
'zcl.json',
'zcl_general.json'
]

coverage_file = 'Debug\\Coverage\\coverage.txt'

def main():
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 34567
    connection.bind(("127.0.0.1", port))
    connection.listen(5)
    connection.settimeout(60)
    msg_count = 0
    MAX_N_TEST = 50000
    coverage_analyzer = Coverage()
    total_edges = 0
    total_statements = 0
    coverage_history =[]
    stat_coverage_history = []
    start_time = time.time()
    try:
        if os.path.exists(constant.zstack_log_dir+"zstack_result.txt"):
            os.rename(constant.zstack_log_dir+"zstack_result.txt", constant.zstack_log_dir+"zstack_result_" + str(helpers.get_milli_time()) + ".txt")
        while True:
            (client, address) = connection.accept()
            client.setblocking(1)
            message = client.recv(constant.buffer_size)
            if message is not None:
                convert_seed(message)
                status = execute_zstack(repr(message))
                n_edges = []; n_stats = []
                for cfg_file in target_zcl_cfgs:
                    coverage_analyzer.parse_coverage_result(cfg_dir+cfg_file, coverage_file)
                    n_edges.append(coverage_analyzer.total_edge)
                    n_stats.append(coverage_analyzer.total_statement)
                total_edges = sum(n_edges)
                total_statements = sum(total_statements)
                n_after_edges = coverage_analyzer.calculate_explored_edges()
                n_after_statements = coverage_analyzer.calculate_explored_statements()
                coverage_history.append(n_after_edges)
                stat_coverage_history.append(n_after_statements)
                if msg_count % 100 == 0:
                    logging.info("Msg id: {} with status: {}\n{}".format(msg_count, status, repr(message)))
                    logging.info("Cumulative coverage for edge and statemetns: {}, {}".format(n_after_edges, n_after_statements))
                msg_count+=1

                client.send(str(status))
            if msg_count >= MAX_N_TEST:
                end_time = time.time()
                logging.info(coverage_history[-1])
                logging.info(stat_coverage_history[-1])
                logging.info("Code coverage result: # total stats, # total edges = {} {}\n\
                                    Consumed time: {}\n\
                                    Final # stats, Final # edges = {} {}".format(total_statements, total_edges, round(1.*(end_time-start_time)/60,2), coverage_history[-1], stat_coverage_history[-1]))
                x_list = list(range(MAX_N_TEST+1))
                edge_coverage_list = [0] + coverage_history
                stats_coverage_list = [0] + stat_coverage_history
                edge_coverage_list = [round(edge_coverage_list[i]*1./total_edges, 2) for i in range(len(edge_coverage_list))]
                stats_coverage_list = [round(stats_coverage_list[i]*1./total_statements, 2) for i in range(len(stats_coverage_list))]
                plt.plot(x_list, edge_coverage_list, marker='o', linestyle='-', color='b', label='Z-Fuzzer')
                plt.title('Edge coverage analysis')
                plt.xlabel('# testing cases')
                plt.ylabel('Covered edges')
                plt.savefig('mylog/edge-coverage.png')
                plt.clf()
                plt.plot(x_list, stats_coverage_list, marker='o', linestyle='-', color='b', label='Z-Fuzzer')
                plt.title('Statements coverage analysis')
                plt.xlabel('# testing cases')
                plt.ylabel('Covered statements')
                plt.savefig('mylog/statement-coverage.png')
                break
            else:
                time.sleep(0.5)
    except KeyboardInterrupt:
        connection.close()
        end_time = time.time()
        logging.info(coverage_history[-1])
        logging.info(stat_coverage_history[-1])
        logging.info("Code coverage result: # total stats, # total edges = {} {}\n\
                            Consumed time: {}\n\
                            Final # stats, Final # edges = {} {}".format(total_statements, total_edges, round(1.*(end_time-start_time)/60,2), coverage_history[-1], stat_coverage_history[-1]))
        x_list = list(range(len(coverage_history)+1))
        edge_coverage_list = [0] + coverage_history
        stats_coverage_list = [0] + stat_coverage_history
        edge_coverage_list = [round(edge_coverage_list[i]*1./total_edges, 2) for i in range(len(edge_coverage_list))]
        stats_coverage_list = [round(stats_coverage_list[i]*1./total_statements, 2) for i in range(len(stats_coverage_list))]
        plt.plot(x_list, edge_coverage_list, marker='o', linestyle='-', color='b', label='Z-Fuzzer')
        plt.title('Edge coverage analysis')
        plt.xlabel('# testing cases')
        plt.ylabel('Covered edges')
        plt.savefig('mylog/edge-coverage.png')
        plt.clf()
        plt.plot(x_list, stats_coverage_list, marker='o', linestyle='-', color='b', label='Z-Fuzzer')
        plt.title('Statements coverage analysis')
        plt.xlabel('# testing cases')
        plt.ylabel('Covered statements')
        plt.savefig('mylog/statement-coverage.png')

        sys.exit("User Interrupt!")
    except socket.error, msg:
        connection.close()
        sys.exit("Socket Error:%s" % msg)
    except socket.timeout, msg:
        connection.close()
        sys.exit("Socket Timeout:%s" % msg)

    return


# -------------------------------------------------------------- #
if __name__ == '__main__':
    main()






