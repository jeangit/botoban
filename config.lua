return
{
  -- limit of hosts before banning the whole network
  threshold_for_network = 3,

  -- IP that should not be banned
  do_not_ban = {
    {["100.101.102.103"]="Jean-Seb"},
    {["104.105.106.107"]="My old friend"}
  },

  -- journald logs used for detecting IPs to ban.
  -- format : unit name, time to scan, string to detect
  logs = {
    { "sshd","1 hour", "invalid user" },
    { "postfix", "1 hour", "LOGIN authentication failed" }
  },

  -- database name to use for saving / loading IPs harvested
  database = "database"

}
