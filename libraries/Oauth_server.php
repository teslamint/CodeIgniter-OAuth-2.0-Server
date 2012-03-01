<?php defined('BASEPATH') OR exit('No direct script access allowed');

class Oauth_server {

	protected $ci;

	/**
	 * Constructor.
	 * 
	 * @access public
	 */
	function __construct()
	{
		$this->ci = get_instance();
	}
	
	/**************************************************************
	//! Client stuff
	**************************************************************/
	
	/**
	 * Validates a client's credentials
	 * 
	 * @access public
	 * @param string $client_id
	 * @param mixed $client_secret
	 * @param mixed $redirect_uri
	 * @return bool|object
	 */
	function validate_client($client_id = "", $client_secret = NULL, $redirect_uri = NULL)
	{
		$params = array(
			'client_id' => $client_id,
		);
		
		if ($client_secret !== NULL)
		{
			$params['client_secret'] = $client_secret;
		}
		
		if ($redirect_uri !== NULL)
		{
			$params['redirect_uri'] = $redirect_uri;
		}
	
		$client_check_query = $this->ci->db
										->select(array('name', 'client_id', 'auto_approve'))
										->get_where('applications', $params);
						
		if ($client_check_query->num_rows() == 1)
		{
			return $client_check_query->row();
		}
		
		else
		{
			return FALSE;
		}
	}
	
	/**************************************************************
	//! Auth code stuff
	**************************************************************/

	
	/**
	 * Generates a new authorise code once a user has approved an application
	 * 
	 * @access public
	 * @param mixed $client_id
	 * @param mixed $user_id
	 * @param mixed $redirect_uri
	 * @param array $scopes
	 * @return string
	 */
	function new_auth_code($client_id = '', $user_id = '', $redirect_uri = '', $scopes = array(), $access_token = NULL)
	{		
		// Update an existing session with the new code
		if ($access_token)
		{
			$code = md5(time().uniqid());
			
			$this->ci->db
						->where(array(
							'type_id'		=> $user_id,
							'type'			=> 'user',
							'client_id'		=> $client_id,
							'access_token'	=> $access_token
						))
						->update('oauth_sessions', array(
							'code'			=> $code,
							'stage'			=> 'request',
							'redirect_uri'	=> $redirect_uri, // The applications redirect URI may have been updated
							'last_updated'	=> time()
						));
				
			return $code;
		}
		
		// Create a new oauth session
		else
		{
			// Delete any existing sessions just to be sure
			$this->ci->db
						->delete('oauth_sessions', array(
							'client_id'		=> $client_id,
							'type_id'		=> $user_id,
							'type'			=> 'user'
						));
		
			$code = md5(time().uniqid());
			
			$this->ci->db
						->insert('oauth_sessions', array(
							'client_id'		=>	$client_id,
							'redirect_uri'	=>	$redirect_uri,
							'type_id'		=>	$user_id,
							'type'			=>	'user',
							'code'			=>	$code,
							'first_requested'	=> time(),
							'last_updated'	=>	time(),
							'access_token'	=>	NULL
						));
					
			$session_id = $this->ci->db->insert_id();
			
			// Add the scopes
			foreach ($scopes as $scope)
			{
				$scope = trim($scope);
				
				if(trim($scope) !== "")
				{
					$this->ci->db
								->insert('oauth_session_scopes', array(
									'session_id'	=>	$session_id,
									'scope'			=>	$scope
								));
				}
			}
		}
		
		return $code;
	}
	
	
	/**
	 * validate_auth_code function.
	 * 
	 * @access public
	 * @param string $code
	 * @param string $client_id
	 * @param string $redirect_uri
	 * @return bool|int
	 */
	function validate_auth_code($code = '', $client_id = '', $redirect_uri = '')
	{
		$validate = $this->ci->db
								->select(array('id', 'type_id'))
								->get_where('oauth_sessions', array(
									'client_id'		=> $client_id,
									'redirect_uri'	=> $redirect_uri, 
									'code'			=> $code
								));
		
		if ($validate->num_rows() == 0)
		{
			return FALSE;
		}
		
		else
		{
			$result = $validate->row();
			return $result;
		}
	}
	
	/**************************************************************
	//! Access token stuff
	**************************************************************/	
	/**
	 * Generates a new access token (or returns an existing one)
	 * 
	 * @access public
	 * @param string $session_id. (default: '')
	 * @return string
	 */
	function get_access_token($session_id = '')
	{
		// Check if an access token exists already
		$exists_query = $this->ci->db
									->select('access_token')
									->get_where('oauth_sessions', array(
										'id' => $session_id,
										'access_token IS NOT NULL' => NULL
									));
		
		// If an access token already exists, return it and remove the authorization code
		if ($exists_query->num_rows() == 1)
		{
			// Remove the authorization code
			$this->ci->db
						->where(array('id' => $session_id))
						->update('oauth_sessions', array(
							'code'	=>	NULL,
							'stage'	=>	'granted'
						));
			
			// Return the access token
			$exists = $exists_query->row();
			return $exists->access_token;
		}
		
		// An access token doesn't exist yet so create one and remove the authorization code
		else
		{
			$access_token = sha1(time().uniqid());
			
			$updates = array(
				'code'			=>	NULL,
				'access_token'	=>	$access_token,
				'last_updated'	=>	time(),
				'stage'			=>	'granted'
			);
			
			// Update the OAuth session
			$this->ci->db
						->where(array('id' => $session_id))
						->update('oauth_sessions', $updates);
			
			// Update the session scopes with the access token
			$this->ci->db
						->where(array('session_id' => $session_id))
						->update('oauth_session_scopes', array(
							'access_token'	=>	$access_token
						));

			return $access_token;
		}
	}
		
	/**
	 * Validates an access token
	 * 
	 * @access public
	 * @param string $access_token. (default: "")
	 * @param array $scope. (default: array())
	 * @return void
	 */
	function validate_access_token($access_token = '', $scopes = array())
	{
		// Validate the token exists
		$valid_token = $this->ci->db
									->where(array(
										'access_token'	=>	$access_token
									))
									->get('oauth_sessions');
		
		// The access token doesn't exists
		if ($valid_token->num_rows == 0)
		{
			return FALSE;
		}

		// The access token does exist, validate each scope
		else
		{
			$token = $valid_token->row();
		
			if (count($scopes) > 0)
			{
				foreach ($scopes as $scope)
				{
					$scope_exists = $this->ci->db
												->where(array(
													'access_token'	=>	$access_token,
													'scope'			=>	$scope
												))
												->count_all_results('oauth_session_scopes');
					
					if ($scope_exists == 0)
					{
						return FALSE;
					}
				}
				
				return TRUE;
			}
			
			else
			{
				return TRUE;
			}
		}
		
	}	
	
	/**
	 * Tests if a user has already authorized an application and an access token has been granted
	 * 
	 * @access public
	 * @param string $user_id
	 * @param string $client_id
	 * @return bool
	 */
	function access_token_exists($user_id = '', $client_id = '')
	{
		$token_query = $this->ci->db
									->select('access_token')
									->get_where('oauth_sessions', array(
										'client_id'					=> $client_id,
										'type_id'					=> $user_id,
										'type'						=> 'user',
										'access_token != '			=> '',
										'access_token IS NOT NULL'	=> NULL
									));
		
		if ($token_query->num_rows() === 1)
		{
			return $token_query->row();
		}
		
		else
		{
			return FALSE;
		}
	}
	
	/**************************************************************
	//! Miscellaneous stuff
	**************************************************************/

	function scope_exists($scope)
	{
		$exists = $this->db
							->where('scope', $scope)
							->from('scopes')
							->count_all_results();
		
		return ($exists === 1) ? TRUE : FALSE;
	}
	
	function scope_details($scopes)
	{
		if (is_array($scopes))
		{
			$scope_details = $this->db
									->where_in('scope', $requested_scopes)
									->get('scopes');
		}
		
		else
		{
			$scope_details = $this->db
									->where('scope', $requested_scopes)
									->get('scopes');
		}
		
		$scopes = array();
		
		if ($scope_details->num_rows() > 0)
		{
			foreach ($scope_details->result() as $s)
			{
				$scopes[] = array(
					'name' => $s->name,
					'description' => $s->description
				);
			}
		}
		
		return $scopes;	

	}
	
	/**************************************************************
	//! Miscellaneous stuff
	**************************************************************/
	
	/**
	 * Generates the redirect uri with appended params
	 * 
	 * @access public
	 * @param string $redirect_uri. (default: "")
	 * @param array $params. (default: array())
	 * @return string
	 */
	function redirect_uri($redirect_uri = '', $params = array(), $query_delimeter = '?')
	{
		if (strstr($redirect_uri, $query_delimeter))
		{
			$redirect_uri = $redirect_uri . http_build_query($params);
		}
		else
		{
			$redirect_uri = $redirect_uri . $query_delimeter . http_build_query($params);
		}
		
		return $redirect_uri;
	}
	
		
	/**
	 * Sign the user into your application.
	 *
	 * Edit this function to suit your needs. It must return a user's id as a string
	 * or FALSE if the sign in was incorrect
	 * 
	 * @access public
	 * @return string|bool
	 */
	function validate_user($username = "", $password = "")
	{
		// Your code here
	}
		
}