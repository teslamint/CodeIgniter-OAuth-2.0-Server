<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * OAuth 2.0 resource server library
 *
 * @author              Alex Bilbie | www.alexbilbie.com | alex@alexbilbie.com
 * @copyright   		Copyright (c) 2012, Alex Bilbie.
 * @license             http://www.opensource.org/licenses/mit-license.php
 * @link                https://github.com/alexbilbie/CodeIgniter-OAuth-2.0-Server
 * @version             Version 0.2
 */

class Oauth_resource_server
{
	private $access_token = NULL;
	private $scopes = array();
	private $type = NULL;
	private $type_id = NULL;

	public function __construct()
	{
		$this->ci = get_instance();
		$this->init();
	}
	
	public function init()
	{		
		switch ($this->ci->input->server('REQUEST_METHOD'))
		{
			default:
				$access_token = $this->ci->input->get('access_token');
				break;
				
			case 'PUT':
				$access_token = $this->ci->put('access_token'); // assumes you're using https://github.com/philsturgeon/codeigniter-restserver
				break;
			
			case 'POST':
				$access_token = $this->ci->input->post('access_token');
				break;
				
			case 'DELETE':
				$access_token = $this->ci->delete('access_token'); // https://github.com/philsturgeon/codeigniter-restserver
				break;
		}
		
		if ($access_token)
		{
			$session_query = $this->db->get_where('oauth_sessions', array('access_token' => $access_token, 'stage' => 'granted'));
			
			if ($session_query->num_rows() == 1)
			{
				$session = $session_query->row();
				$this->access_token = $session->access_token;
				$this->type = $session->type;
				$this->type_id = $session->type_id;
				
				$scopes_query = $this->db->get_where('oauth_session_scopes', array('access_token' => $access_token));
				if ($scopes_query->num_rows() > 0)
				{
					foreach ($scopes_query->result() as $scope)
					{
						$this->scopes[] = $scope->scope;
					}
				}
			}
			
			else
			{
				$this->ci->output->set_status_header(403);
				$this->ci->output->set_output('Invalid access token');
			}
		}
		
		else
		{
			$this->ci->output->set_status_header(403);
			$this->ci->output->set_output('Missing access token');
		}
	}
	
	public function is_user()
	{
		if ($this->type == 'user')
		{
			return $this->type_id;
		}
		
		return FALSE;
	}
	
	public function is_anon()
	{
		if ($this->type == 'anon')
		{
			return $this->type_id;
		}
		
		return FALSE;
	}
	
	public function has_scope($scopes)
	{
		if (is_string($scopes))
		{
			if (in_array($scopes, $this->scopes))
			{
				return TRUE;
			}
			
			return FALSE;
		}
		
		elseif (is_array($scopes))
		{
			foreach ($scopes as $scope)
			{
				if ( ! in_array($scope, $this->scopes))
				{
					return FALSE;
				}
			}
			
			return TRUE;
		}
		
		return FALSE;
	}
}