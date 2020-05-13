return
{
  -- limit of hosts per network before banning the whole network
  threshold_for_network = 3,
  -- limit of tries from the same host before banning him
  threshold_for_hosts = 100,

  -- remove rules when no hit on the host
  remove_no_match = true,

  -- IP that should not be banned
  whitelist = {
    ["100.101.102.103"]="Jean-Seb",
    ["104.105.106.107"]="My old friend"
  },

  -- journald logs used for detecting IPs to ban.
  -- format :
  -- unit name, time to scan, string to detect (for journald)
  -- "dmesg" , pattern_to_search (for dmesg)
  logs = {
    { "sshd","1 hour", "invalid user" },
    { "postfix", "1 hour", "LOGIN authentication failed" },
    { "dmesg", "", "ssh" },
    -- blacklist and whitelist are using another format
    -- "blacklist" or "whitelist", "ip_file", "port", "chain"
    -- those lists contains *networks* ip lists (_not_ hosts!)
    { "whitelist", "ip_french.txt", "23", "INPUT" }
  },

  -- database name to use for saving / loading IPs harvested
  database = "database"

}
