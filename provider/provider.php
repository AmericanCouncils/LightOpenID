<?php
/**
 * Partial implementation of LightOpenIDProviderCore that's appropriate for
 * classic flat PHP scripts.
 */

ini_set('error_log','log');

abstract class LightOpenIDProvider extends LightOpenIDProviderCore
{
    /**
     * Stores an association in the PHP session.
     * @param String $handle Association handle -- should be used as a key.
     * @param Array $assoc Association data.
     */
    protected function setAssoc($handle, $assoc)
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
    protected function getAssoc($handle)
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
    protected function delAssoc($handle)
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

    protected function getLocation()
    {
        return (!empty($_SERVER['HTTPS']) ? 'https' : 'http') . '://'
            . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }

    protected function getQuery()
    {
        return $_GET + $_POST;
    }

    protected function isHttps()
    {
        return !empty($_SERVER['HTTPS'])
    }

    protected function isUserAgentAcceptingXrds()
    {
        return isset($_SERVER['HTTP_ACCEPT']) &&
            strpos($_SERVER['HTTP_ACCEPT'], 'application/xrds+xml') !== false);
    }
}
