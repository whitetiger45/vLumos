#!/bin/python3
# -*- coding: utf-8 -*-
# author: bryan kanu
# version 2.1
# https://developers.virustotal.com/reference/analyses-object
# https://developers.virustotal.com/reference/file-info
# https://developers.virustotal.com/reference/files
# todo
# https://developers.virustotal.com/reference/file-all-behaviours-summary
# https://developers.virustotal.com/reference/file-behaviour-summary
# https://developers.virustotal.com/reference/get-a-summary-of-all-mitre-attck-techniques-observed-in-a-file
from datetime import datetime, timedelta, timezone
from getpass import getpass
from multiprocessing import Process, Lock
from pathlib import Path
from string import Template
import argparse, asyncio, json
import requests, sys, traceback
sys.path.insert(0,"evocatio")
import evocatio

deflate = lambda lst: list(filter((lambda l: l != b""),lst))
get_files = lambda paths : list(filter((lambda path: path.is_file()),paths))
get_timestamp = lambda : datetime.strftime(datetime.utcnow()+timedelta(hours=-4),"%m-%d-%y.%H-%M-%S")

HASHIFIED_HASHES_FNAME = ""
CURRENT_TIME = get_timestamp()
vLUMOS_ANALYSIS_REPORT_FNAME = f"vLumos.analysis.report.{CURRENT_TIME}"
vLUMOS_ANALYSIS_STATUS_FNAME = f"vLumos.analysis.scan.status.{CURRENT_TIME}.txt"

M_API_KEY = None
M_HEADER = {"Accept":"application/json"}
VT_API_URL = "https://www.virustotal.com/api/v3/"
VT_SIGNUP_URL = "https://www.virustotal.com/gui/join-us"
MISSING_API_KEY_MESSAGE = f"Try again with a valid VirusTotal API key (visit {VT_SIGNUP_URL} to get started)"
STATUS = 0

prog_description = "Shine a light on suspicious files on your system, or urls you stumble across on the web"
parser = argparse.ArgumentParser(prog=f"vLumos", description=prog_description)
parser.add_argument("-k", "--key", dest="m_api_key", action="store_true", help="VirusTotal API Key")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--search", dest="search", metavar="SEARCH_VALUE", 
    type=str, help="A single hash to search VirusTotal for")
group.add_argument("-i", "--input-file", dest="input_file", metavar="INPUT FILE",
    type=Path, help="Hashified hashes (file containing one or more [FILE_NAME FILE_HASH] pairs) to search VirusTotal for")
input_file_group = parser.add_argument_group("INPUT-FILE OPTIONS")
input_file_group.add_argument("-e", "--estimate", dest="estimate_only", action="store_true", help="Calculate time to scan all hashes in INPUT FILE")
argv = parser.parse_args()        

async def calc_time_to_complete():
    global STATUS
    try:
        hourly_limit = get_vt_account_hourly_limit()["user"]["allowed"]
        objects = get_file_line_count(HASHIFIED_HASHES_FNAME)
        # https://stackoverflow.com/questions/51846547/how-to-convert-float-into-hours-minutes-seconds
        hours,seconds = divmod(((objects/hourly_limit))*60,3600)
        minutes,seconds = divmod(seconds,60)
        total_time_to_complete_scan = f"{hours:02.0f}:{minutes:02.0f}:{seconds:02.0f}"
        print(f"[*] VirusTotal account requests hourly limit: {hourly_limit} requests / hr")
        print(f"[*] Number of objects to query in {HASHIFIED_HASHES_FNAME}: {objects}")
        print(f"[*] Estimated total time to complete scan: {total_time_to_complete_scan}")
    except:
        print(f"[x] {traceback.format_exc()}")
        STATUS = 2

def get_and_write_search_info(**item):
    global STATUS
    url = VT_API_URL + f"search?query={item['obj']}"
    try:
        response = get_url(url)        
        report_fd = Path(vLUMOS_ANALYSIS_REPORT_FNAME)
        if report_fd.exists() and report_fd.is_file():
            tmp = json.loads(report_fd.read_text())
            tmp.append(response)
            report_fd.write_text(json.dumps(tmp,indent=4))
        else:
            report_fd.write_text(json.dumps([response],indent=4))                        
    except:
        print(f"[x] {traceback.format_exc()}")
        STATUS = -1

def get_file_line_count(f_name):
    lc = None
    try:
        fd = Path(f_name)
        lc = len(deflate(fd.read_bytes().split(b"\n")))
    except:
        print(f"[x] {traceback.format_exc()}")
    return lc

def get_query_objs_from_file(f_name):
    data = []
    try:
        fd = Path(f_name)
        if not fd.exists() or not fd.is_file():
            return data
        data = fd.read_text().split("\n")
    except:
        print(f"[x] {traceback.format_exc()}")
    return data

def get_url(url,header=None):
    global M_HEADER
    try:
        if header:
            M_HEADER = header
        response = requests.get(url,headers=M_HEADER)
        if hasattr(response,"json"):
            try:
                response = response.json()
            except:
                if hasattr(response,"_content"):
                    response = response._content.decode("utf-8")
                elif hasattr(response,"text"):
                    resposne = response.text
        elif hasattr(response,"text"):
            response = response.text
    except:
        print(f"[x] {traceback.format_exc()}")
    else:
        return response

def get_vt_account_hourly_limit():
    try:
        url = VT_API_URL + f"users/{M_API_KEY}/overall_quotas"
        response = get_url(url)
    except:
        print(f"[x] {traceback.format_exc()}")
    else:
        return response['data']['api_requests_hourly']

async def main():
    global HASHIFIED_HASHES_FNAME    
    try:
        if not Path(CURRENT_TIME).is_dir():
            Path(CURRENT_TIME).mkdir()
        if argv.input_file:
                HASHIFIED_HASHES_FNAME = argv.input_file
                if not M_API_KEY:
                    set_vt_api_key()
                if M_API_KEY:
                    await calc_time_to_complete()
                    if argv.estimate_only:
                        return STATUS
                    print("[*] Rate limit requests enabled")
                    await rate_limit_requests()
                else:
                    print(f"[x] {MISSING_API_KEY_MESSAGE}")
                    return 1
        else:
            # https://docs.python.org/3/library/asyncio-queue.html#examples
            search = {"obj":argv.search}
            if not M_API_KEY:
                set_vt_api_key()
            if M_API_KEY:
                print("[*] Rate limit requests disabled")
                api_endpoints = [
                    VT_API_URL + f"search?query={search['obj']}",
                    VT_API_URL + f"graphs?filter={search['obj']}"
                ]                
                urls_q = asyncio.Queue(); tasks = []
                urls_q.put_nowait(api_endpoints[0])
                urls_q.put_nowait(api_endpoints[1])
                # task = asyncio.create_task(vLumosMaxima(search, queue))
                # append twice to send concurrent requests to the two endpoints
                tasks.append(asyncio.create_task(vLumosMaxima(urls_q)))
                tasks.append(asyncio.create_task(vLumosMaxima(urls_q)))                
                # get_and_write_search_info(**search)
                # await vLumosMaxima(urls_q)
                await urls_q.join()
                try:
                    tasks[0].cancel();tasks[1].cancel();
                    await asyncio.gather(*tasks, return_exceptions=True)
                except:
                    pass
            else:
                print(f"[x] {MISSING_API_KEY_MESSAGE}")
                return 1
    except:
        print(f"[x] {traceback.format_exc()}")
        return 1
    return STATUS

async def rate_limit_requests():
    global STATUS
    try:
        hourly_limit = get_vt_account_hourly_limit(); rate = 0
        numThreads = 4        
        rate = int(hourly_limit['user']['allowed']/60)
        objects = get_query_objs_from_file(HASHIFIED_HASHES_FNAME)
        virusTotal = {
            "search":Template("""$_host/search?query=$_q"""),
            "graph":Template("""$_host/graphs?filter=$_q""")
        }                    
        urls_q = asyncio.Queue(); tasks = []
        totalObjects = len(objects)
        objsStr = ""; taskCount = 0; objs_idx = 0
        if hourly_limit['user']['used'] != hourly_limit['user']['allowed']:
            while objects:
                print(f"[*] querying object {objs_idx+1}/{totalObjects}")
                obj = objects.pop(0)
                task1 = virusTotal["search"].substitute(_host=VT_API_URL,_q=obj)
                task2 = virusTotal["graph"].substitute(_host=VT_API_URL,_q=obj)
                urls_q.put_nowait(task1); urls_q.put_nowait(task2)
                objsStr += f"{obj}\n"                
                for idx_y in range(0,numThreads):
                    tasks.append(asyncio.create_task(vLumosMaxima(urls_q)))
                    taskCount += 1
                await urls_q.join()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                update_status_file(objsStr)
                objsStr = ""
                if taskCount % rate == 0 and objects:                    
                    await asyncio.sleep(60)
                objs_idx += 1
    except:
        print(f"[x] {traceback.format_exc()}")
        STATUS = 3

def set_vt_api_key():
    global M_API_KEY, M_HEADER
    ATTEMPTS = 1;
    if not argv.m_api_key:
        try:
            while not M_API_KEY and ATTEMPTS < 4:
                M_API_KEY = getpass("VirusTotal API Key> ")
                ATTEMPTS += 1
        except:
            print(f"[x] {traceback.format_exc()}")
    else:
        M_API_KEY = argv.m_api_key

    if M_API_KEY:
        M_HEADER.update({"X-Apikey": M_API_KEY})
    print("")

def update_status_file(line):
    global ACTUAL_COUNT
    try:
        with open(f"{CURRENT_TIME}/{vLUMOS_ANALYSIS_STATUS_FNAME}","a") as fd:
            fd.write(f"{line}")
    except:
        print(f"[x] {traceback.format_exc()}")

async def vLumosMaxima(url_queue):
    global STATUS
    try:
        url = await url_queue.get()
        response = get_url(url)
        query = url.split("?")[1]
        endpoint = query.split("=")[0]; query = query.split("=")[1];
        report_fd = Path(f"{CURRENT_TIME}/{endpoint}.{query}.json")
        if report_fd.exists() and report_fd.is_file():
            tmp = json.loads(report_fd.read_text())
            tmp.append(response)
            report_fd.write_text(json.dumps(tmp,indent=4))
        else:
            report_fd.write_text(json.dumps([response],indent=4))
    except:
        error_check = f"[x] {traceback.format_exc()}"
        if "await url_queue.get()" not in error_check:
            print(error_check)
    finally:
        url_queue.task_done()

if __name__ == "__main__":
    try:
        print("\n*** vLumos ***\n")        
        STATUS = asyncio.run(main())
        if STATUS == 0 and not argv.estimate_only:
            print(f"[*] vLumos output written to {CURRENT_TIME}")
        elif STATUS != 0:
            print(f"[!] An error occured. Return code: {STATUS}")
    except:
        print(f"[x] {traceback.format_exc()}")
