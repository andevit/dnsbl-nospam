<?php
/**
 * Plugin DNSBL No spam
 *
 * @wordpress-plugin
 *
 * Plugin Name:          DNSBL - No Spam
 * Plugin URI:           https://www.andev.it
 * Description:          Check IP  DNSBL
 * Version:              1.1.5
 * Author:               andev.it
 * Author URI:           https://www.andev.it
 */

add_action( 'wpcf7_init', 'wpcf7_add_form_tag_dnsbl', 10, 0 );

function wpcf7_add_form_tag_dnsbl() {
    wpcf7_add_form_tag( 'dnsbl',
        'wpcf7_dnsbl_form_tag_handler',
        array(
            'name-attr' => true,
        )
    );
}

function wpcf7_dnsbl_form_tag_handler( $tag ) {
    if ( empty( $tag->name ) ) {
        return '';
    }

    $validation_error = wpcf7_get_validation_error( $tag->name );

    $class = wpcf7_form_controls_class( $tag->type );

    if ( $validation_error ) {
        $class .= ' wpcf7-not-valid';
    }

    $item_atts = array(
        'type' => 'hidden',
        'name' => 'c_'.date('Ymd'),
        'value' => '1',
        'class' => $tag->get_class_option() ? $tag->get_class_option() : null,
        'id' => $tag->get_id_option(),
    );

    if ( $validation_error ) {
        $item_atts['aria-invalid'] = 'true';
        $item_atts['aria-describedby'] = wpcf7_get_validation_error_reference(
            $tag->name
        );
    } else {
        $item_atts['aria-invalid'] = 'false';
    }

    $item_atts = wpcf7_format_atts( $item_atts );

    $content = empty( $tag->content )
        ? (string) reset( $tag->values )
        : $tag->content;

    $content = trim( $content );

    if ( $content ) {

        $html = sprintf(
            '<input %1$s />',
            $item_atts
        );

    } else {
        $html = sprintf(
            '<div><input %1$s /></div>',
            $item_atts
        );
    }

    return $html;
}

add_action("wpcf7_before_send_mail", "wpcf7_do_something_else");
function wpcf7_do_something_else($cf7) {

    $onlyItalyIP = TRUE;

    // get the contact form object
    $wpcf = WPCF7_ContactForm::get_current();

    $key_email = 'your-email';
    $key_message = 'your-message';

    // Controllo link http:/ - https:// - .com/ - .ru/
    if(stripos($_REQUEST[$key_message], 'http://') !== FALSE || stripos($_REQUEST[$key_message],'.ru/') )
    {
        $wpcf->skip_mail = true;
        return $wpcf;
    }
    else
    {
        // DNSBL Check IP
        require_once dirname(__FILE__).'/vendor/autoload.php';
        require_once dirname(__FILE__).'/spamfilter.php';

        if(!isset($_REQUEST['c_'.date('Ymd')]))
        {
            $wpcf->skip_mail = true;
            return $wpcf;
        }

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
            return $wpcf;
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
                        return $wpcf;
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
                return $wpcf;
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
                    return $wpcf;
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
