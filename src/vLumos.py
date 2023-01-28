# -*- coding: utf-8 -*-
#!/bin/python3
# author: bryan kanu
# https://developers.virustotal.com/reference/analyses-object
# https://developers.virustotal.com/reference/file-info
# https://developers.virustotal.com/reference/files
# todo
# https://developers.virustotal.com/reference/file-all-behaviours-summary
# https://developers.virustotal.com/reference/file-behaviour-summary
# https://developers.virustotal.com/reference/get-a-summary-of-all-mitre-attck-techniques-observed-in-a-file
from datetime import datetime, date, time, timezone
from getpass import getpass
from multiprocessing import Process, Lock
from pathlib import Path
import argparse, asyncio, json
import requests, sys, traceback
sys.path.insert(0,"evocatio")
import evocatio

deflate = lambda lst: list(filter((lambda l: l != b""),lst))
get_files = lambda paths : list(filter((lambda path: path.is_file()),paths))
get_timestamp = lambda : datetime.now(timezone.utc).strftime('%m-%d-%y.%H-%M-%S')

HASHIFIED_HASHES_FNAME = ""
CURRENT_TIME = get_timestamp()
vLUMOS_ANALYSIS_REPORT_FNAME = f"vLumos.analysis.report.{CURRENT_TIME}.json"
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
        number_of_hashes = get_file_line_count(HASHIFIED_HASHES_FNAME)
        # https://stackoverflow.com/questions/51846547/how-to-convert-float-into-hours-minutes-seconds
        hours,seconds = divmod(((number_of_hashes/hourly_limit))*60,3600)
        minutes,seconds = divmod(seconds,60)
        total_time_to_complete_scan = f"{hours:02.0f}:{minutes:02.0f}:{seconds:02.0f}"
        print(f"[*] VirusTotal account requests hourly limit: {hourly_limit} requests / hr")
        print(f"[*] Number of hashes in {HASHIFIED_HASHES_FNAME}: {number_of_hashes}")
        print(f"[*] Estimated total time to complete scan: {total_time_to_complete_scan}")
    except:
        print(f"[x] {traceback.format_exc()}")
        STATUS = 2

async def main():
    global HASHIFIED_HASHES_FNAME
    try:
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
            # blame: https://docs.python.org/3/library/asyncio-queue.html#examples
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
                await vLumosMaxima(urls_q)
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
        if hourly_limit['user']['allowed'] < 60:
            rate = int(60/hourly_limit['user']['allowed'])
        file_hashes = get_file_hashes(HASHIFIED_HASHES_FNAME)
        file_hashes = list(set(file_hashes) - set(get_file_hashes(vLUMOS_ANALYSIS_STATUS_FNAME)))
        file_hashes = list(filter((lambda line : line != b""),file_hashes))
        if hourly_limit['user']['used'] != hourly_limit['user']['allowed']:
            for file_hash_line in file_hashes:
                r_file_hash_line = file_hash_line[::-1].partition(b" ")
                file_name = r_file_hash_line[2][::-1].decode("utf-8")
                object = r_file_hash_line[0][::-1].decode("utf-8")
                await asyncio.sleep(rate)
                search = {"obj":object}
                get_and_write_search_info(**search)
                if STATUS != 0:
                    break
                update_status_file(file_hash_line.decode("utf-8"))
    except:
        print(f"[x] {traceback.format_exc()}")
        STATUS = 3

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

async def vLumosMaxima(url_queue):
    global STATUS
    try:
        url = await url_queue.get()
        response = get_url(url)        
        report_fd = Path(vLUMOS_ANALYSIS_REPORT_FNAME)
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

def get_file_hashes(f_name):
    file_hashes = []
    try:
        fd = Path(f_name)
        if not fd.exists() or not fd.is_file():
            return file_hashes
        file_hashes = fd.read_bytes().split(b"\n")
    except:
        print(f"[x] {traceback.format_exc()}")
    return file_hashes

def get_file_line_count(f_name):
    lc = None
    try:
        fd = Path(f_name)
        lc = len(deflate(fd.read_bytes().split(b"\n")))
    except:
        print(f"[x] {traceback.format_exc()}")
    return lc

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
        with open(vLUMOS_ANALYSIS_STATUS_FNAME,"a") as fd:
            fd.write(f"{line}\n")
    except:
        print(f"[x] {traceback.format_exc()}")

if __name__ == "__main__":
    try:
        print("\n*** vLumos ***\n")        
        STATUS = asyncio.run(main())
        if STATUS == 0 and not argv.estimate_only:
            print(f"[*] vLumos output written to {vLUMOS_ANALYSIS_REPORT_FNAME}")
        elif STATUS != 0:
            print(f"[!] An error occured. Return code: {STATUS}")
    except:
        print(f"[x] {traceback.format_exc()}")
