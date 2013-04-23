<?php
/**
 * Partial implementation of LightOpenIDProviderCore that's appropriate for
 * classic flat PHP scripts.
 */

require('providerCore.php');
ini_set('error_log','log');

abstract class LightOpenIDProvider extends LightOpenIDProviderCore
{
    /**
     * Stores an association in the PHP session.
     * @param String $handle Association handle -- should be used as a key.
     * @param Array $assoc Association data.
     */
    function setAssoc($handle, $assoc)
    {
        $oldSession = session_id();
        session_commit();
        session_id($assoc['handle']);
        session_start();
        $_SESSION['assoc'] = $assoc;
        session_commit();
        if($oldSession) {
            session_id($oldSession);
            session_start();
        }
    }
    
    /**
     * Retreives association data from the PHP session.
     * @param String $handle Association handle.
     * @return Array Association data.
     */
    function getAssoc($handle)
    {
        $oldSession = session_id();
        session_commit();
        session_id($handle);
        session_start();
        $assoc = null;
        if(!empty($_SESSION['assoc'])) {
            $assoc = $_SESSION['assoc'];
        }
        session_commit();
        if($oldSession) {
            session_id($oldSession);
            session_start();
        }
        return $assoc;
    }
    
    /**
     * Deletes an association from the PHP session.
     * @param String $handle Association handle.
     */
    function delAssoc($handle)
    {
        $oldSession = session_id();
        session_commit();
        session_id($handle);
        session_start();
        session_destroy();
        if($oldSession) {
            session_id($oldSession);
            session_start();
        }
    }

    function getLocation()
    {
        return (!empty($_SERVER['HTTPS']) ? 'https' : 'http') . '://'
            . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }

    function getQuery()
    {
        return $_GET + $_POST;
    }

    function isHttps()
    {
        return !empty($_SERVER['HTTPS']);
    }

    function isUserAgentAcceptingXrds()
    {
        return isset($_SERVER['HTTP_ACCEPT']) &&
            strpos($_SERVER['HTTP_ACCEPT'], 'application/xrds+xml') !== false;
    }

    function createResponse($code, $content, $headers)
    {
        if ($code != 200) {
            header(':', true, $code);
        }
        foreach ($headers as $k => $v) {
            header("$k: $v");
        }
        echo $content;
    }
}
