rule Meterpreter_rev_tcp
{

        strings:
		
		$url1 = "https://blockchain.info/address/13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"
		$url2 = "https://blockchain.info/address/12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"
		$url3 = "https://blockchain.info/address/115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn"
		$tor1 = "gx7ekbenv2riucmf.onion"
		$tor2 = "57g7spgrzlojinas.onion"
		$tor3 = "xxlvbrloxvriy2c5.onion"
		$tor4 = "76jdd2ir2embyv47.onion"
		$tor5 = "cwwnhwhlz52maqm7.onion"
		

        condition:
              $url1 or any of them
}
