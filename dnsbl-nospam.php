<?php
/**
 * Plugin DNSBL No spam
 *
 * @wordpress-plugin
 *
 * Plugin Name:          DNSBL - No Spam
 * Plugin URI:           https://www.andev.it
 * Description:          Check IP  DNSBL
 * Version:              1.0.4
 * Author:               andev.it
 * Author URI:           https://www.andev.it
 */

function restrict_admin() {

    $key_email = 'email';
    $key_message = 'your-message';

    if ( !is_user_logged_in() && $_SERVER['REQUEST_METHOD'] == 'POST' && ( wp_doing_ajax() || (strpos($_SERVER["REQUEST_URI"],'/wp-json/contact-form-7/v1/contact-forms/') !== FALSE && strpos($_SERVER["REQUEST_URI"],'/feedback') !== FALSE) ) ) {
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
            wp_mail('andrea.pagliarani@gmail.com', "[".$_SERVER['SERVER_NAME']."] SPAM DETECT " . get_client_ip(), implode(',',$return) . ' - ' . implode(',', $_POST));
            exit();
        }
        else
        {
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
                        wp_mail('andrea.pagliarani@gmail.com', "[".$_SERVER['SERVER_NAME']."] SPAM DETECT IP " . get_client_ip(), implode(',',$return) . ' - ' . implode(',', $_POST));
                        exit();
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
                wp_mail('andrea.pagliarani@gmail.com', "[".$_SERVER['SERVER_NAME']."] SPAM DETECT #2 " . get_client_ip(),  implode(',', $_POST));
                exit();
            }
            elseif($_REQUEST[$key_email])
            {
                $validator = new \Egulias\EmailValidator\EmailValidator();
                $multipleValidations = new \Egulias\EmailValidator\Validation\MultipleValidationWithAnd([
                    new \Egulias\EmailValidator\Validation\RFCValidation(),
                    new \Egulias\EmailValidator\Validation\DNSCheckValidation()
                ]);

                if(!$validator->isValid($_REQUEST[$key_email], $multipleValidations))
                {
                    wp_mail('andrea.pagliarani@gmail.com', "[".$_SERVER['SERVER_NAME']."] SPAM DETECT #3 " . get_client_ip(),  implode(',', $_POST));
                    exit();
                }
            }
        }
    }
}
add_action( 'init', 'restrict_admin', 1 );

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
