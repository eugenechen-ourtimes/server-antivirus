import argparse
import csv
import datetime
from os.path import join
import sys

class Utils:
    class GetComputerFilePathsStatus:
        ok = 0
        error_splitting_ip = 1 # error splitting ip
        no_data = 2 # no data for such subnet

    def splitIp(ip):
        emptyIp = (0, 0, 0, 0)
        lst = ip.split(".")
        if len(lst) != 4:
            return 1, emptyIp

        s1, s2, s3, s4 = lst
        if (
            len(s1) == 0 or len(s1) > 3 or
            len(s2) == 0 or len(s2) > 3 or
            len(s3) == 0 or len(s3) > 3 or
            len(s4) == 0 or len(s4) > 3
        ):
            return 2, emptyIp

        try:
            i1 = int(s1)
            i2 = int(s2)
            i3 = int(s3)
            i4 = int(s4)
            if (
                i1 < 0 or i1 > 255 or
                i2 < 0 or i2 > 255 or
                i3 < 0 or i3 > 255 or
                i4 < 0 or i4 > 255
            ):
                return 4, emptyIp
            return 0, (i1, i2, i3, i4)

        except:
            return 3, emptyIp

    def getComputerFilePaths(ip):
        emptyComputerFilePath = ""
        splitIpStatus, (i1, i2, i3, i4) = Utils.splitIp(ip)
        if splitIpStatus != 0:
            return Utils.GetComputerFilePathsStatus.error_splitting_ip, (emptyComputerFilePath, emptyComputerFilePath)

        if i1 != 192 or i2 != 168:
            return Utils.GetComputerFilePathsStatus.no_data, (emptyComputerFilePath, emptyComputerFilePath)

        if i3 == 0:
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net0.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net0.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if i3 == 1:
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net1.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net1.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if i3 == 2:
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net2.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net2.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if i3 == 3:
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net3.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net3.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if i3 == 4:
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net4.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net4.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        return Utils.GetComputerFilePathsStatus.no_data, (emptyComputerFilePath, emptyComputerFilePath)

    def getApexOneInstalledCount(baseDatetime, ip, computerFilePath):
        def isOfflineForAaLongTime(offlineDateTimeStr):
            if offlineDateTimeStr == "無":
                return False

            offlineDateStr, offlineTimeStr = offlineDateTimeStr.split(" ")
            offlineYearStr, offlineMonthStr, offlineDayStr = offlineDateStr.split("/")
            offlineHourStr, offlineMinuteStr = offlineTimeStr.split(":")
            offlineYear = int(offlineYearStr)
            offlineMonth = int(offlineMonthStr)
            offlineDay = int(offlineDayStr)
            offlineHour = int(offlineHourStr)
            offlineMinute = int(offlineMinuteStr)
            offlineDatetime = datetime.datetime(offlineYear, offlineMonth, offlineDay, offlineHour, offlineMinute)

            timedelta = baseDatetime - offlineDatetime
            return timedelta.days >= 14

        apexOneInstalledCount = 0
        with open(computerFilePath, mode = "r", encoding = "big5", newline = "") as computerFile:
            reader = csv.DictReader(computerFile)
            for computer in reader:
                computer_ip = computer["ip"]
                computer_offline_datetime = computer["offline_datetime"]
                if computer_ip == ip and not isOfflineForAaLongTime(computer_offline_datetime):
                    apexOneInstalledCount += 1

        return apexOneInstalledCount

    def getDeepSecurityInstalledCount(baseDatetime, ip, computerFilePath):
        def isOfflineForAaLongTime(lastCommunicationStr):
            if "Ago" in lastCommunicationStr:
                return False

            offlineDateStr, offlineTimeStr = lastCommunicationStr.split(" ")
            offlineYearStr, offlineMonthStr, offlineDayStr = offlineDateStr.split("/")
            offlineHourStr, offlineMinuteStr = offlineTimeStr.split(":")
            offlineYear = int(offlineYearStr)
            offlineMonth = int(offlineMonthStr)
            offlineDay = int(offlineDayStr)
            offlineHour = int(offlineHourStr)
            offlineMinute = int(offlineMinuteStr)
            offlineDatetime = datetime.datetime(offlineYear, offlineMonth, offlineDay, offlineHour, offlineMinute)

            timedelta = baseDatetime - offlineDatetime
            return timedelta.days >= 14

        deepSecurityInstalledCount = 0
        with open(computerFilePath, mode = "r", encoding = "big5", newline = "") as computerFile:
            reader = csv.DictReader(computerFile)
            for computer in reader:
                computer_ip = computer["ip"]
                computer_last_communication = computer["last_communication"]
                if computer_ip == ip and not isOfflineForAaLongTime(computer_last_communication):
                    deepSecurityInstalledCount += 1

        return deepSecurityInstalledCount

def main(args):
    base_datetime = args.base_time
    ip = args.ip

    if base_datetime is None:
        print("need to provide a time as a base")
        sys.exit(0)

    if ip is None:
        print("need an IP address")
        sys.exit(0)

    getComputerFilePathsStatus, (apexOneComputerFilePath, deepSecurityComputerFilePath) = Utils.getComputerFilePaths(ip)
    if getComputerFilePathsStatus == Utils.GetComputerFilePathsStatus.error_splitting_ip:
        print("error splitting ip")
        sys.exit(0)

    if getComputerFilePathsStatus == Utils.GetComputerFilePathsStatus.no_data:
        print("no data for such subnet")
        sys.exit(0)

    xss = [
        ["192.168.0.1", "192.168.1.1", "192.168.2.1", "192.168.3.1", "192.168.4.1"]
    ]

    excludedIps = [
        x
        for xs in xss
        for x in xs
    ]

    if ip in excludedIps:
        print("ip is excluded")
        sys.exit(0)

    apexOneInstalledCount = Utils.getApexOneInstalledCount(base_datetime, ip, apexOneComputerFilePath)
    deepSecurityInstalledCount = Utils.getDeepSecurityInstalledCount(base_datetime, ip, deepSecurityComputerFilePath)

    s1, s2, s3, s4 = ip.split(".")
    i1 = int(s1)
    i2 = int(s2)
    i3 = int(s3)
    i4 = int(s4)

    print("%d.%d.%d.%03d" % (i1, i2, i3, i4))
    print("Apex One:      %2d" % (apexOneInstalledCount))
    print("Deep Security: %2d" % (deepSecurityInstalledCount))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "show antiviruses of a computer")
    parser.add_argument('--base-time', type=datetime.datetime.fromisoformat, metavar = "[base-time]", help="ISO format: [YYYY-MM-DD]T[HH:mm:ss]")
    parser.add_argument("--ip", metavar = "[ip]", help="IP address")

    main(parser.parse_args())
