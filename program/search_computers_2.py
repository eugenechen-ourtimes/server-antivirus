import argparse
import csv
import datetime
from os.path import join
import sys

class Utils:
    class GetComputerFilePathsStatus:
        ok = 0
        no_data = 1 # no data for such subnet

    def getComputerFilePaths(subnetName):
        if subnetName.lower() == "net0":
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net0.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net0.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if subnetName.lower() == "net1":
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net1.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net1.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if subnetName.lower() == "net2":
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net2.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net2.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if subnetName.lower() == "net3":
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net3.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net3.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        if subnetName.lower() == "net4":
            apexOneComputerFilePath = join("../data/input/antivirus", "apex-srvfrm", "apex-srvfrm-net4.csv")
            deepSecurityComputerFilePath = join("../data/input/antivirus", "apex-dp", "apex-dp-net4.csv")
            return Utils.GetComputerFilePathsStatus.ok, (apexOneComputerFilePath, deepSecurityComputerFilePath)

        emptyComputerFilePath = ""
        return Utils.GetComputerFilePathsStatus.no_data, (emptyComputerFilePath, emptyComputerFilePath)

def main(args):
    base_datetime = args.base_time
    subnet_name = args.subnet_name

    def getApexOneInstalledCounts(computerFilePath):
        apexOneInstalledCounts = [0] * 256
        with open(computerFilePath, mode = "r", encoding = "big5", newline = "") as computerFile:
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

                timedelta = base_datetime - offlineDatetime
                return timedelta.days >= 14

            reader = csv.DictReader(computerFile)
            for computer in reader:
                computer_ip = computer["ip"]
                computer_offline_datetime = computer["offline_datetime"]
                if not isOfflineForAaLongTime(computer_offline_datetime):
                    i4 = int(computer_ip.split(".")[3])
                    apexOneInstalledCounts[i4] += 1

        return apexOneInstalledCounts

    def getDeepSecurityInstalledCounts(computerFilePath):
        deepSecurityInstalledCounts = [0] * 256
        with open(computerFilePath, mode = "r", encoding = "big5", newline = "") as computerFile:
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

                timedelta = base_datetime - offlineDatetime
                return timedelta.days >= 14

            reader = csv.DictReader(computerFile)
            for computer in reader:
                computer_ip = computer["ip"]
                computer_last_communication = computer["last_communication"]
                if not isOfflineForAaLongTime(computer_last_communication):
                    i4 = int(computer_ip.split(".")[3])
                    deepSecurityInstalledCounts[i4] += 1

        return deepSecurityInstalledCounts

    if base_datetime is None:
        print("need to provide a time as a base")
        sys.exit(0)

    if subnet_name is None:
        print("need to provide a subnet")
        sys.exit(0)

    getComputerFilePathsStatus, (apexOneComputerFilePath, deepSecurityComputerFilePath) = Utils.getComputerFilePaths(subnet_name)
    if getComputerFilePathsStatus == Utils.GetComputerFilePathsStatus.no_data:
        print("no data for such subnet")
        sys.exit(0)

    apexOneInstalledCounts = getApexOneInstalledCounts(apexOneComputerFilePath)
    deepSecurityInstalledCounts = getDeepSecurityInstalledCounts(deepSecurityComputerFilePath)

    xss = [
        ["192.168.0.1", "192.168.1.1", "192.168.2.1", "192.168.3.1", "192.168.4.1"]
    ]

    excludedIps = [
        x
        for xs in xss
        for x in xs
    ]

    def getPrefix():
        if subnet_name == "net0":
            return "192.168.0."

        if subnet_name == "net1":
            return "192.168.1."

        if subnet_name == "net2":
            return "192.168.2."

        if subnet_name == "net3":
            return "192.168.3."

        if subnet_name == "net4":
            return "192.168.4."

        return ""
    
    prefix = getPrefix()
    for i4 in range(1, 255):
        print(prefix + str(i4).zfill(3))
        if prefix + str(i4) in excludedIps:
            print("ip is excluded")
            continue

        apexOneInstalledCount = apexOneInstalledCounts[i4]
        deepSecurityInstalledCount = deepSecurityInstalledCounts[i4]
        print("Apex One:      %2d" % (apexOneInstalledCount))
        print("Deep Security: %2d" % (deepSecurityInstalledCount))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "show antiviruses of computers in a given subnet")
    parser.add_argument('--base-time', type=datetime.datetime.fromisoformat, metavar = "[base-time]", help="ISO format: [YYYY-MM-DD]T[HH:mm:ss]")
    parser.add_argument("--subnet-name", metavar = "[subnet-name]", help="net0 / net1 / net2 / net3 / net4")

    main(parser.parse_args())
