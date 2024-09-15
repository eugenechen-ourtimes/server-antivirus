import argparse
import csv
from os.path import join
import sys

class Utils:
    class GetComputerFilePathStatus:
        ok = 0
        no_data = 1 # no data for such subnet

    def getGetComputerFilePath(subnetName):
        if subnetName.lower() == "net0":
            computerFilePath = join("../data/output", "ip-mn-net0.csv")
            return Utils.GetComputerFilePathStatus.ok, computerFilePath

        if subnetName.lower() == "net1":
            computerFilePath = join("../data/output", "ip-mn-net1.csv")
            return Utils.GetComputerFilePathStatus.ok, computerFilePath

        if subnetName.lower() == "net2":
            computerFilePath = join("../data/output", "ip-mn-net2.csv")
            return Utils.GetComputerFilePathStatus.ok, computerFilePath

        if subnetName.lower() == "net3":
            computerFilePath = join("../data/output", "ip-mn-net3.csv")
            return Utils.GetComputerFilePathStatus.ok, computerFilePath

        if subnetName.lower() == "net4":
            computerFilePath = join("../data/output", "ip-mn-net4.csv")
            return Utils.GetComputerFilePathStatus.ok, computerFilePath

        emptyComputerFilePath = ""
        return Utils.GetComputerFilePathStatus.no_data, emptyComputerFilePath

def main(args):
    subnet_name = args.subnet_name
    if subnet_name is None:
        print("need to provide a subnet")
        sys.exit(0)

    getComputerFilePathStatus, computerFilePath = Utils.getGetComputerFilePath(subnet_name)
    if getComputerFilePathStatus == Utils.GetComputerFilePathStatus.no_data:
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

    with open(computerFilePath, mode = "r", encoding = "big5", newline = "") as computerFile:
        reader = csv.DictReader(computerFile)
        unknownExpectedAntivirusCount = 0
        expectedApexOneCount = 0
        expectedDeepSecurityCount = 0
        actualApexOneCount = 0
        actualDeepSecurityCount = 0

        ipsNa = []
        ipsWithExpectedAndActualAntivirusDifferent = []
        ipsWithExpectedAntivirusNoneButInstalled = []
        for computer in reader:
            computer_expected_antivirus = computer["expected_antivirus"]
            computer_actual_antivirus = computer["actual_antivirus"]
            computer_private_ip = computer["private_ip"]
            if computer_private_ip in excludedIps:
                ipsNa.append(computer_private_ip)
                continue

            if computer_expected_antivirus == "A":
                expectedApexOneCount += 1
                if computer_actual_antivirus == "A":
                    actualApexOneCount += 1
                if computer_actual_antivirus == "D":
                    ipsWithExpectedAndActualAntivirusDifferent.append(computer_private_ip)

            elif computer_expected_antivirus == "D":
                expectedDeepSecurityCount += 1
                if computer_actual_antivirus == "A":
                    ipsWithExpectedAndActualAntivirusDifferent.append(computer_private_ip)
                elif computer_actual_antivirus == "D":
                    actualDeepSecurityCount += 1

            elif computer_expected_antivirus == "X":
                if computer_actual_antivirus == "A" or computer_actual_antivirus == "D":
                    ipsWithExpectedAntivirusNoneButInstalled.append(computer_private_ip)

            elif computer_expected_antivirus == "?":
                unknownExpectedAntivirusCount += 1

        print("NA: ", end = "")
        print(ipsNa)

        print("antivirus shouldn\'t be installed: ", end = "")
        print(ipsWithExpectedAntivirusNoneButInstalled)

        print("antivirus different than expected: ", end = "")
        print(ipsWithExpectedAndActualAntivirusDifferent)

        print()

        print("unknown expected antivirus: %d" % (unknownExpectedAntivirusCount))
        print("Apex One: %d/%d" % (actualApexOneCount, expectedApexOneCount))
        print("Deep Security: %d/%d" % (actualDeepSecurityCount, expectedDeepSecurityCount))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "show statistics")
    parser.add_argument("--subnet-name", metavar = "[subnet name]", help="net0 / net1 / net2 / net3 / net4")

    main(parser.parse_args())
