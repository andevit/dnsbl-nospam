<?php
/**
 * Plugin DNSBL No spam
 *
 * @wordpress-plugin
 *
 * Plugin Name:          DNSBL - No Spam
 * Plugin URI:           https://www.andev.it
 * Description:          Check IP  DNSBL
 * Version:              1.1.3
 * Author:               andev.it
 * Author URI:           https://www.andev.it
 */

add_action("wpcf7_before_send_mail", "wpcf7_do_something_else");
function wpcf7_do_something_else($cf7) {
    
    $onlyItalyIP = TRUE;
    
    // get the contact form object
    $wpcf = WPCF7_ContactForm::get_current();

    $key_email = 'contact-email';
    $key_message = 'contact-message';

    // Controllo link http:/ - https:// - .com/ - .ru/
    if(stripos($_REQUEST[$key_message], 'http://') !== FALSE || stripos($_REQUEST[$key_message], 'https://') !== FALSE || stripos($_REQUEST[$key_message],'.com/') || stripos($_REQUEST[$key_message],'.ru/') )
    {
        $wpcf->skip_mail = true;
    }
    else
    {
        // DNSBL Check IP
        require_once dirname(__FILE__).'/vendor/autoload.php';
        require_once dirname(__FILE__).'/spamfilter.php';

        $dnsbl = new \DNSBL\DNSBL(array(
            'blacklists' => array(
                "bl.mxrbl.com",
                "all.s5h.net",
                "z.mailspike.net",
                "bl.spamcop.net",
                "spam.dnsbl.sorbs.net"
            )
        ));
        $return = $dnsbl->getListingBlacklists(get_client_ip());
        if( count($return) > 0 )
        {
            $wpcf->skip_mail = true;
        }
        else
        {
            // List blacklist Check IP
            $ipsarray = ['danme' => 'https://www.dan.me.uk/torlist/?exit'];
            @mkdir(dirname(__FILE__) . '/ipsblacklist/');
            foreach($ipsarray as $n => $i)
            {
                $filename = dirname(__FILE__) . '/ipsblacklist/'.$n.'.txt';
                if (!file_exists($filename) || (date('U', filemtime($filename)) < time() - 3600*6) || filesize($filename) < 50 ) {
                    $ips = file_get_contents($i);
                    file_put_contents($filename, $ips);
                }

                if (file_exists($filename))
                {
                    $data = file_get_contents($filename);
                    $data2 = explode(PHP_EOL, $data);
                    if(in_array(trim(get_client_ip()), $data2) !== FALSE)
                    {
                        $wpcf->skip_mail = true;
                    }
                }
            }

            // Search in all available blacklists
            if(isset($_REQUEST[$key_message])){
                $filter = new SpamFilter();
                $result = $filter->check_text($_REQUEST[$key_message]);
            }

            if(isset($result) && $result)
            {
                $wpcf->skip_mail = true;
            }
            elseif($_REQUEST[$key_email])
            {
                // Validate email from
                $validator = new \Egulias\EmailValidator\EmailValidator();
                $multipleValidations = new \Egulias\EmailValidator\Validation\MultipleValidationWithAnd([
                    new \Egulias\EmailValidator\Validation\RFCValidation(),
                    new \Egulias\EmailValidator\Validation\DNSCheckValidation()
                ]);

                if(!$validator->isValid($_REQUEST[$key_email], $multipleValidations))
                {
                    $wpcf->skip_mail = true;
                }
            }
        }
    }
    
    if($onlyItalyIP)
    {
        try{
            $ch=curl_init();
            curl_setopt($ch,CURLOPT_URL,"http://www.geoplugin.net/json.gp?ip=" . get_client_ip());
            curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
            curl_setopt($ch,CURLOPT_HEADER, false);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10); //timeout in seconds
            $result=curl_exec($ch);
            curl_close($ch);
            $result = json_decode($result, TRUE);
            if($result['geoplugin_countryCode'] != 'IT')
            {
                $wpcf->skip_mail = true;
            }
        }catch (\Exception $e)
        {

        }

    }
    
    if( $wpcf->skip_mail ) add_filter('wpcf7_skip_mail','__return_true');
    return $wpcf;
}

function get_client_ip() {
    $ipaddress = '';
    if (getenv('HTTP_CLIENT_IP'))
        $ipaddress = getenv('HTTP_CLIENT_IP');
    else if(getenv('HTTP_X_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
    else if(getenv('HTTP_X_FORWARDED'))
        $ipaddress = getenv('HTTP_X_FORWARDED');
    else if(getenv('HTTP_FORWARDED_FOR'))
        $ipaddress = getenv('HTTP_FORWARDED_FOR');
    else if(getenv('HTTP_FORWARDED'))
        $ipaddress = getenv('HTTP_FORWARDED');
    else if(getenv('REMOTE_ADDR'))
        $ipaddress = getenv('REMOTE_ADDR');
    else
        $ipaddress = 'UNKNOWN';
    return $ipaddress;
}
