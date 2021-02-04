// All stable releases
var RelVers = [
"386.1_0",
"384.19_1*",
"384.19_0",
"384.18_0*",
"384.17_0",
"384.16_0*",
"384.15_0*",
"384.14_1*",
"384.14_0",
"384.13_1*",
"384.13_0",
"384.12_0",
"384.11_2*",
"384.11_1",
"384.11_0",
"384.10_0",
"384.9_1",
"384.9_0",
"384.8_3",
"384.8_2",
"384.8_0",
"384.7_2",
"384.7_0",
"384.6_0",
"384.5_3",
"384.5_2",
"384.5_0",
"384.4_3",
"384.4_2",
"384.4_0",
"384.3_0"
];

function fw_info_gen(version)
{
    var fw = {};

    fw.fname = "RT-N18U_" + version + ".trx";
    fw.fnote = version.replace(".", "_") + "_note.txt"
    fw.fchecksum = fw.fname + ".sha256"
    fw.url = "RT-N18U/" + fw.fname;
    fw.url_checksum = "RT-N18U/" + fw.fchecksum;
    return fw;
}

function fw_data_set()
{
    var data_set = [];

    for (let i = 1; i < RelVers.length; i++) {
        var fw_data = [];
        var recommend = !(RelVers[i].indexOf("*") < 0);

        // column 'ID'
        fw_data.push(RelVers[i].replace("*", ""));
        // column 'Version'
        if (recommend)
            fw_data.push("<b>" + RelVers[i].replace("_0", "") + "</b>");
        else
            fw_data.push(RelVers[i].replace("_0", ""));

        data_set.push(fw_data);
    }

    return data_set;
}
