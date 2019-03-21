var cpuInfo, memInfo = new Object();
var tmpInfo;
cpuInfo = <%cpu_usage();%>;
memInfo = <%memory_usage();%>;
tmpInfo = <%temperature_status();%>;
