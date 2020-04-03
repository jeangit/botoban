return
{
  -- limit of hosts per network before banning the whole network
  threshold_for_network = 3,
  -- limit of tries from the same host before banning him
  threshold_for_hosts = 100,

  -- IP that should not be banned
  whitelist = {
    ["100.101.102.103"]="Jean-Seb",
    ["104.105.106.107"]="My old friend"
  },

  -- journald logs used for detecting IPs to ban.
  -- format : unit name, time to scan, string to detect
  logs = {
    { "sshd","1 week", "invalid user" },
    { "postfix", "1 week", "LOGIN authentication failed" }
  },

  -- database name to use for saving / loading IPs harvested
  database = "database"

}
