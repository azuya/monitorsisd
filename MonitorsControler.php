<?php

namespace App\Http\Controllers;

use Illuminate\Routing\Route;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use TCG\Voyager\Database\Schema\SchemaManager;
use TCG\Voyager\Facades\Voyager;
use DataTables;
use App\Monitor;
use Config;

class MonitorsController extends \TCG\Voyager\Http\Controllers\VoyagerBaseController
{

	//...
	private $so, $monitor, $dbdesa, $json = ['whois' => 'DOMAIN NOT FOUND', 'ip_address' => '', 'sid_info' => ''];

	public function __construct(Request $request)
	{
		// $slug = $this->getSlug($request);
		// die($slug);
		$this->so = \MTS\Factories::getDevices()->getLocalHost()->getShell('bash', true);
		// \MTS\Factories::getActions()->getRemoteUsers()->changeUser($this->so, 'root', 'sisddiskominfo2020');
		$this->so->killLastProcess();
		// $this->getinfodesa($request->input('id'));
	}


	//***************************************
	//                _____
	//               |  __ \
	//               | |__) |
	//               |  _  /
	//               | | \ \
	//               |_|  \_\
	//
	//  Read an item of our Data Type B(R)EAD
	//
	//****************************************

	public function show(Request $request, $id)
	{
		$slug = $this->getSlug($request);

		$dataType = Voyager::model('DataType')->where('slug', '=', $slug)->first();

		$isSoftDeleted = false;


		if (strlen($dataType->model_name) != 0) {
			$model = app($dataType->model_name);

			// Use withTrashed() if model uses SoftDeletes and if toggle is selected
			if ($model && in_array(SoftDeletes::class, class_uses_recursive($model))) {
				$model = $model->withTrashed();
			}
			if ($dataType->scope && $dataType->scope != '' && method_exists($model, 'scope' . ucfirst($dataType->scope))) {
				$model = $model->{$dataType->scope}();
			}
			$dataTypeContent = call_user_func([$model, 'findOrFail'], $id);
			if ($dataTypeContent->deleted_at) {
				$isSoftDeleted = true;
			}
		} else {
			// If Model doest exist, get data from table name
			$dataTypeContent = DB::table($dataType->name)->where('id', $id)->first();
		}

		// Replace relationships' keys for labels and create READ links if a slug is provided.
		$dataTypeContent = $this->resolveRelations($dataTypeContent, $dataType, true);

		// If a column has a relationship associated with it, we do not want to show that field
		$this->removeRelationshipField($dataType, 'read');

		// Check permission
		$this->authorize('read', $dataTypeContent);

		// Check if BREAD is Translatable
		$isModelTranslatable = is_bread_translatable($dataTypeContent);

		// Eagerload Relations
		$this->eagerLoadRelations($dataTypeContent, $dataType, 'read', $isModelTranslatable);

		$view = 'voyager::bread.read';

		if (view()->exists("voyager::$slug.read")) {
			$view = "voyager::$slug.read";
		}



		//if (!$dataTypeContent->sid_info) $this->getinfodesa($id, true);

		return Voyager::view($view, compact('dataType', 'dataTypeContent', 'isModelTranslatable', 'isSoftDeleted'));
	}


	private function getinfodesa($id, $isajax = false)
	{

		$this->dbdesa = false;
		// $sidssh = (trim(setting('admin.ssh_sid')));
		// var_dump($sidssh);
		$this->monitor 	= Monitor::find($id);
		if (!$this->monitor) return false;
		// var_dump($this->monitor);
		//if ((!$this->monitor->domain_registered || !$this->monitor->ip_address ) && $isajax == false) return false;
		if ($isajax == false) return false;

		$domain 	= explode("://", $this->monitor->url);
		$domain 	= str_replace("/", "",  $domain[1]);
		$sid_info	=	[
			"error"				=> 	true, 		"id_kec"	=>	false,
			"website_title"		=> 	false,		"web_theme"	=> 	false,
			"current_version"	=>	false
		];
		//cek dulu whois nya kalo ga terdaftar return false aja ....

		//cek instaasi Opensid
		$desadir =  DIRECTORY_SEPARATOR . "home" . DIRECTORY_SEPARATOR .
			$this->monitor->id_kec . DIRECTORY_SEPARATOR .
			"web" . DIRECTORY_SEPARATOR .
			$domain . DIRECTORY_SEPARATOR .
			"public_html" . DIRECTORY_SEPARATOR .
			$domain . DIRECTORY_SEPARATOR .
			"config" . DIRECTORY_SEPARATOR . 'database.php';

		if (is_file($desadir)) {
			include $desadir;
		} else {
			// ini kode production, hanya cek domain yang di hosting di server SISD diskominfo, beri komentar kalau mau cek develop mode
			$sid_info["error"] = 'Hosting diluar server SID Diskominfo Bogorkab';
			$this->monitor->sid_info = $sid_info;
			$this->monitor->save();
			return $this->json;

			// development mode, untuk trial error, useless ketika kode diatas diaktifkan
			\MTS\Factories::getActions()->getRemoteUsers()->changeUser($this->so, 'root', 'sisddiskominfo2020');
			$cek  =  $this->so->exeCmd('find /home/ -name "' . $domain . '"', false, 3000);
			$cek = explode("\r\n", $cek);
			$cek = trim($cek[(count($cek) - 1)]);


			$file_include = $cek . "/config/database.php";
			if (is_file($file_include)) {
				include($file_include);
			} elseif (is_file(DIRECTORY_SEPARATOR . "home" . DIRECTORY_SEPARATOR .
				$this->monitor->id_kec . DIRECTORY_SEPARATOR .
				"web" . DIRECTORY_SEPARATOR .
				$domain . DIRECTORY_SEPARATOR .
				"public_html")) {
				$sid_info["error"] = 'OpenSID Belum terinstall';
				$this->monitor->sid_info = $sid_info;
				$this->monitor->save();
				return $this->json;
			} else {
				$sid_info["error"] = 'Hosting diluar server SID Diskominfo Bogorkab';
				$this->monitor->sid_info = $sid_info;
				$this->monitor->save();
				return $this->json;
			}
		}

		Config::set('database.connections.webdesa' . $id, [
			'driver'    => 'mysql',
			'host'      => $db['default']['hostname'],
			'port'      => '3306',
			'database'  => $db['default']['database'],
			'username'  => $db['default']['username'],
			'password'  => $db['default']['password'],
			// 'database'  => '01_1001',
			// 'username'  => '01_1001',
			// 'password'  => "Diskominfo011001",
		]);

		// }
		try {
			$this->dbdesa = DB::connection('webdesa' . $id)->table('setting_aplikasi')
				->where('kategori', "=", 'web')
				->orWhere('kategori', "=", 'readonly');
			$sid_info['id_kec'] = $this->monitor->id_kec;
			foreach ($this->dbdesa->get() as $key => $value) {
				//if ($value->key == 'current_version') $this->monitor->sid_info = $value->value;
				$sid_info[$value->key] = $value->value;
				//echo "{$value->key}  --->  {$value->value} <br>";
			}
			$sid_info["error"] = false;
			$this->monitor->sid_info = $sid_info;
			$this->monitor->save();
			$this->json['sid_info'] = $sid_info;
		} catch (\Throwable $th) {
			throw $th;
			die($domain);
			return $this->json;
		}
		return $this->json;
	}
	private function getinfodomain($id, $isajax = false)
	{

		$this->dbdesa = false;
		// $sidssh = (trim(setting('admin.ssh_sid')));
		// var_dump($sidssh);
		$this->monitor 	= Monitor::find($id);
		if (!$this->monitor) return false;
		// var_dump($this->monitor);
		//if ((!$this->monitor->domain_registered || !$this->monitor->ip_address ) && $isajax == false) return false;
		if ($isajax == false) return false;

		$domain 	= explode("://", $this->monitor->url);
		$domain 	= str_replace("/", "",  $domain[1]);

		//cek dulu whois nya kalo ga terdaftar return false aja ....
		$return1  =  $this->so->exeCmd("whois {$domain}");
		$ret = str_replace("\nID ccTLD whois server\r", "", $return1);
		$ret = str_replace("\nPlease see 'whois -h whois.id help' for usage.\r\n\n", "", $ret);
		$rows = explode("\n", $ret);
		$arr = array('info' => "");
		foreach ($rows as $row) {
			$posOfFirstColon = strpos($row, ": ");
			if ($posOfFirstColon === FALSE) {
				$row	= trim($row, "\r");
				if ($row  == 'DOMAIN NOT FOUND') {
					$arr['info'] =  $row;
					$arr['details'] = '';
				} else {
					$arr['info'] .=  $row . "\n";
				}
			} else {
				$arr['details'][substr($row, 0, $posOfFirstColon)] = trim(substr($row, $posOfFirstColon + 1));
			}
		}
		$ret = $arr;
		$this->monitor->domain_registered = $ret;
		$this->monitor->save();
		$this->json['whois'] = $ret;
		if ($arr['info'] == 'DOMAIN NOT FOUND') {
			return $this->json;
		} else {

			// kalo terdaftar cek A record nya hosting dimana 
			$ret = trim($this->so->exeCmd("dig @localhost {$domain} A +short"));

			$this->monitor->ip_address = $ret;
			$this->monitor->save();
			$this->json['ip_address'] = $ret;
		}

		return $this->json;
	}


	public function check(Request $request)
	{
		// GET THE DataType based on the slug
		$dataType = Voyager::model('DataType')->where('slug', '=', "monitors")->first();
		$this->authorize('browse', app($dataType->model_name));

		// Check permission
		//$this->authorize('browse', app($dataType->model_name));

		$this->getinfodomain($request->input('id'), true);

		return json_encode($this->getinfodesa($request->input('id'), true));
	}

	public function checksid(Request $request)
	{
		$dataType = Voyager::model('DataType')->where('slug', '=', "monitors")->first();
		$this->authorize('browse', app($dataType->model_name));

		// Check permission
		//$this->authorize('browse', app($dataType->model_name));

		//$this->getinfodesa($request->input('id'), true);

		return json_encode($this->getinfodesa($request->input('id'), true));
	}

	public function fixhtaccess(Request $request)
	{
		$dataType = Voyager::model('DataType')->where('slug', '=', "monitors")->first();
		$this->authorize('browse', app($dataType->model_name));

		if (!$request->ajax()) return false;

		$json 	= ['success' => false, 'message' => 'Unknown '];
		$id		=	$request->input('id');


		$this->monitor 	= Monitor::find($id);
		if (!$this->monitor) {
			$json['message'] = 'ID Domain tidak ditemukan';
			return $json;
		};

		$domain 	= explode("://", $this->monitor->url);
		$domain 	= str_replace("/", "",  $domain[1]);

		$public_html = '/home/' . $this->monitor->id_kec . '/web/' . $domain . '/public_html/';
		if (!is_dir($public_html)) {
			$cek  =  $this->so->exeCmd('find /home/ -name "' . $domain . '"');
			$cek = explode("\r\n", $cek);
			$cek = trim($cek[0]) . '/public_html/';
			if (is_dir($cek)) {
				$public_html = $cek;
			} else {
				$json['message'] = 'Folder public_html tidak ditemukan!';
				return $json;
			}
		}

		$this->so->exeCmd('cp -f /home/admin/share/SISD/.htaccess ' . $public_html);
		$json['success'] = true;
		$json['message'] = 'Berhasil memperbaiki file .htaccess dan permission folder Silahkan  Cek website!';
		$user = $this->monitor->id_kec ?: $this->_getdomainowner($public_html);
		$this->so->exeCmd('chown -R ' . $user . ':' . $user . ' ' . $public_html);

		return $json;

		//copy htacess master ke folder html domain direktori


	}

	private function _getdomainowner($folder)
	{

		$info 	= str_replace('/home/', '', $folder);
		$info 	= explode('/', $info);
		return $info[0];
	}

	public function fixpermission(Request $request)
	{
		$dataType = Voyager::model('DataType')->where('slug', '=', "monitors")->first();
		$this->authorize('browse', app($dataType->model_name));

		if (!$request->ajax()) return false;

		$json 	= ['success' => false, 'message' => 'Unknown '];
		$id		=	$request->input('id');


		$this->monitor 	= Monitor::find($id);
		if (!$this->monitor) {
			$json['message'] = 'ID Domain tidak ditemukan';
			return $json;
		};

		$domain 	= explode("://", $this->monitor->url);
		$domain 	= str_replace("/", "",  $domain[1]);

		$public_html = '/home/' . $this->monitor->id_kec . '/web/' . $domain . '/public_html/';
		if (!is_dir($public_html)) {
			$cek  =  $this->so->exeCmd('find /home/ -name "' . $domain . '"');
			$cek = explode("\r\n", $cek);
			$cek = trim($cek[0]) . '/public_html/';
			if (is_dir($cek)) {
				$public_html = $cek;
			} else {
				$json['message'] = 'Folder public_html tidak ditemukan!';
				return $json;
			}
		}

		$this->so->exeCmd('cp -f /home/admin/share/SISD/.htaccess ' . $public_html);
		$json['success'] = true;
		$json['message'] = 'Berhasil memperbaiki file .htaccess dan permission folder Silahkan  Cek website!';
		$user = $this->monitor->id_kec ?: $this->_getdomainowner($public_html);
		$this->so->exeCmd('chown -R ' . $user . ':' . $user . ' ' . $public_html);

		return $json;
	}

	public function install(Request $request)
	{
		$dataType = Voyager::model('DataType')->where('slug', '=', "monitors")->first();
		$this->authorize('browse', app($dataType->model_name));

		if (!$request->ajax()) return false;

		$json 	= ['success' => false, 'message' => 'Unknown '];
		$id		=	$request->input('id');
		$password =	$request->input('random');


		$this->monitor 	= Monitor::find($id);
		if (!$this->monitor) {
			$json['message'] = 'ID Domain tidak ditemukan';
			return $json;
		};

		$domain 	= explode("://", $this->monitor->url);
		$domain 	= str_replace("/", "",  $domain[1]);
		$json = ['finish' => false, 'next' => '', 'progress' => '50%', 'message' => 'Memulai upgrade'];
		$status = $request->input('next');
		$sharefolder = '/home/admin/share/SISD' . DIRECTORY_SEPARATOR;
		$public_html = '/home/' . $this->monitor->id_kec . '/web/' . $domain . '/public_html/';
		\MTS\Factories::getActions()->getRemoteUsers()->changeUser($this->so, 'root', 'sisddiskominfo2020');
		$this->so->exeCmd('chown -R admin:admin ' . $public_html);

		Config::set('database.connections.webdesa' . $id, [
			'driver'    => 'mysql',
			'host'      => 'localhost',
			'port'      => '3306',
			'database'  => $this->monitor->id_kec . '_' . $this->monitor->id_desa,
			'username'  => $this->monitor->id_kec . '_' . $this->monitor->id_desa,
			'password'  => 'Diskominfo' . $this->monitor->id_kec . $this->monitor->id_desa,
		]);

		switch ($status) {
				// case 'start':
			case 'mulai':
				$json['progress'] = '40%';
				$json['next'] = 'installdatabase';
				$json['message'] = 'Instalasi database ... <br>(mungkin membutuhkan waktu yang agak lama +- 5 menit, jangan refresh halaman)';
				return json_encode($json);
				break;

			case 'installdatabase':

				// }
				try {
					$this->dbdesa = DB::connection('webdesa' . $id)->table('setting_aplikasi')
						->where('kategori', "=", 'web')
						->orWhere('kategori', "=", 'readonly');
					$sid_info['id_kec'] = $this->monitor->id_kec;
					$rec = $this->dbdesa->get();
				} catch (\Throwable $th) {
					$rec = false;
				} finally {
					if ($rec === false) {
						$sql_script = $sharefolder . 'contoh_data_awal_20210401.sql';

						try {
							ini_set('max_execution_time', '500');
							ini_set('set_time_limit', '500');
							$this->dbdesa = DB::connection('webdesa' . $id)->unprepared(file_get_contents($sql_script));
							$proses = 'ok';
							//code...
						} catch (\Throwable $th) {
							//throw $th;
							$proses = $th;
						} finally {
							if ($proses == 'ok') {
								$this->dbdesa = DB::connection('webdesa' . $id)->table('setting_aplikasi')
									->where('kategori', "=", 'web')
									->orWhere('kategori', "=", 'readonly');
								$sid_info['id_kec'] = $this->monitor->id_kec;
								foreach ($this->dbdesa->get() as $key => $value) {
									//if ($value->key == 'current_version') $this->monitor->sid_info = $value->value;
									$sid_info[$value->key] = $value->value;
									//echo "{$value->key}  --->  {$value->value} <br>";
								}
								$sid_info["error"] = false;
								$this->monitor->sid_info = $sid_info;
								$this->monitor->save();
								/** @todo rubah default konfigurasi desa melalui script wizzard, seperti nama desa, kecamatan kode desa dan lain lain
								 * 
								 */
								$json['progress'] = '70%';
								$json['next'] = 'tema';
								$json['message'] = 'Instalasi database selesai. Memulai seting Konfigurasi aplikasi ';
							} else {
								$json['progress'] = '100%';
								$json['finish'] = 'true';
								$json['message'] = $proses->getMessage();
							}
						}
						ini_set('max_execution_time', '120');
					} else {
						$this->dbdesa = DB::connection('webdesa' . $id)->table('setting_aplikasi')
							->where('kategori', "=", 'web')
							->orWhere('kategori', "=", 'readonly');
						$sid_info['id_kec'] = $this->monitor->id_kec;
						foreach ($this->dbdesa->get() as $key => $value) {
							//if ($value->key == 'current_version') $this->monitor->sid_info = $value->value;
							$sid_info[$value->key] = $value->value;
							//echo "{$value->key}  --->  {$value->value} <br>";
						}
						$sid_info["error"] = false;
						$this->monitor->sid_info = $sid_info;
						$this->monitor->save();
						/** @todo rubah default konfigurasi desa melalui script wizzard, seperti nama desa, kecamatan kode desa dan lain lain
						 * 
						 */
						$json['progress'] = '70%';
						$json['next'] = 'tema';
						$json['message'] = 'Instalasi database selesai. Memulai seting Konfigurasi aplikasi ';

						json_encode($this->getinfodesa($id, true));

						$json['progress'] = '100%';
						$json['next'] = 'next';
						$json['message'] = 'Ada kesalahan install. Sepertinya sistem sudah terpasang. Melanjutkan fungsi upgrade ...';
					}
				}

				break;
			case 'next':
				//copy folder asset dari share ke domain
				$json['message'] .= 'Copy assets. ' . $this->so->exeCmd('cp -r ' . $sharefolder . 'assets ' . $public_html);
				//copy folder desa dari share ke domain dan rubah ke nama domain
				$json['message'] .= '<br>Copy desa folder. ' . $this->so->exeCmd('cp -r ' . $sharefolder . 'desa-contoh ' . $public_html . $domain);
				//buat folder log
				$json['message'] .= '<br>Membuat folder log desa folder. ' . $this->so->exeCmd('mkdir  ' . $public_html . 'logs');
				//copy securimage folder
				$json['message'] .= '<br>Copy securimage folder. ' . $this->so->exeCmd('cp -r ' . $sharefolder . 'securimage ' . $public_html);
				//buat shortcut themes
				$json['message'] .= '<br>Shortcut themes. ' . $this->so->exeCmd('ln -s ' . $sharefolder . 'themes ' . $public_html . 'themes');

				$json['progress'] = '80%';
				$json['next'] = 'copyingfile';
				$json['message'] .= 'Menyalin file asset, tema, dan template surat...';
				break;

			case 'copyingfile':
				//copy htaccess
				$this->so->exeCmd('cp -f ' . $sharefolder . 'robot.txt ' . $public_html);
				//copy htaccess
				$json['message'] .= '<br>Copy .htaccess. ' . $this->so->exeCmd('cp -f ' . $sharefolder . '.htaccess ' . $public_html);
				//copy sertifikat
				$json['message'] .= '<br>Copy sertifikat. ' . $this->so->exeCmd('cp -f ' . $sharefolder . 'cacert.pem ' . $public_html);
				//copy index.php
				$json['message'] .= '<br>Copy securimage folder. ' . $this->so->exeCmd('cp -f ' . $sharefolder . 'index.php ' . $public_html);
				//copy favicon.ico
				$json['message'] .= '<br>Copy securimage folder. ' . $this->so->exeCmd('cp -f ' . $sharefolder . 'favicon.ico ' . $public_html);

				$json['progress'] = '90%';
				$json['next'] = 'fixpermission';
				$json['message'] .= 'Memperbarui file .htaccess dan per-izinan berkas serta folder...';
				break;


			case 'fixpermission':
				//memperbaiki folder permission
				//merubah file konfig database 
				$file = $public_html . $domain . '/config/database.php';
				$username 	= $this->monitor->id_kec . '_' . $this->monitor->id_desa;
				$password	=	'Diskominfo' . $this->monitor->id_kec . $this->monitor->id_desa;
				//merubah $db['default']['username'] = 'root';
				file_put_contents($file, str_replace(
					'[\'username\'] = \'root\';',
					'[\'username\'] = \'' . $username . '\';',
					file_get_contents($file)
				));
				//merubah $db['default']['password'] = '';
				file_put_contents($file, str_replace(
					'[\'password\'] = \'\';',
					'[\'password\'] = \'' . $password . '\';',
					file_get_contents($file)
				));
				//merubah $db['default']['database'] = 'opensid';
				file_put_contents($file, str_replace(
					'[\'database\'] = \'opensid\';',
					'[\'database\'] = \'' . $username . '\';',
					file_get_contents($file)
				));

				$json['progress'] = '95%';
				$json['next'] = 'finish';
				$json['message'] = 'Membersihkan cache dan file yang tidak diperlukan...';
				break;

			case 'finish':
				$this->so->exeCmd('rm -f  ' . $public_html . 'index.html');
				$json['message'] .= '<br>Fix Folder Permission. ' . $this->so->exeCmd('chown -R ' . $this->monitor->id_kec . ':' . $this->monitor->id_kec . ' ' . $public_html);
				//rubah password default admin

				$randomNum = substr(str_shuffle("ABCDEFGHIJKLMNPQRSTUWXYZ123456789"), 0, 5);
				$pass = md5($randomNum);
				$username 	= $this->monitor->id_kec . '_' . $this->monitor->id_desa;
				$this->dbdesa = DB::connection('webdesa' . $id)->table('user')
					->where('id', '1')
					->update(['password' => $pass, 'username' => 'admin_' . $username]);
				if ($this->dbdesa) {
					$json['message'] = 'Password berhasil dirubah....<br>Password baru adalah <strong>' . $pass . '</strong>';
				}

				$json['progress'] = '100%';
				$json['finish'] = 'true';
				$json['message'] = 'Instalasi OpenSID versi 21.04  telah selesai! Simpan informasi admin dan segera rubah password.<br> silahkan cek website <a href="' . $this->monitor->url . '/siteman" target="_blank">User : admin_' . $username . '<br>Password : <strong>' . $randomNum . '</strong></a>';
				break;
			default:
				# code...
				$json['progress'] = '30%';
				$json['next'] = 'mulai';
				$json['message'] = 'Menyiapkan file yang dibutuhkan, Versi Open SID yg dipakai : 21.04 <br>.......';
				return json_encode($json);

				break;
		}
		return json_encode($json);
	}

	public function changepasswordadmin(Request $request)
	{
		$dataType = Voyager::model('DataType')->where('slug', '=', "monitors")->first();
		$this->authorize('browse', app($dataType->model_name));

		if (!$request->ajax()) return false;

		$json 	= ['success' => false, 'message' => 'Unknown '];
		$id		=	$request->input('id');
		$password =	$request->input('random');


		$this->monitor 	= Monitor::find($id);
		if (!$this->monitor) {
			$json['message'] = 'ID Domain tidak ditemukan';
			return $json;
		};
		$domain 	= explode("://", $this->monitor->url);
		$domain 	= str_replace("/", "",  $domain[1]);

		//cek instaasi Opensid
		$desadir =  DIRECTORY_SEPARATOR . "home" . DIRECTORY_SEPARATOR .
			$this->monitor->id_kec . DIRECTORY_SEPARATOR .
			"web" . DIRECTORY_SEPARATOR .
			$domain . DIRECTORY_SEPARATOR .
			"public_html" . DIRECTORY_SEPARATOR .
			$domain . DIRECTORY_SEPARATOR .
			"config" . DIRECTORY_SEPARATOR . 'database.php';

		if (is_file($desadir)) {
			include $desadir;
		} else {


			$cek  =  $this->so->exeCmd('find /home/ -name "' . $domain . '"');
			$cek = explode("\r\n", $cek);
			$cek = trim($cek[(count($cek) - 1)]);


			$file_include = $cek . "/config/database.php";
			if (is_file($file_include)) {
				include($file_include);
			} else {
				$json['message'] = 'Database tidak ditemukan!';
				return $json;
			}
		}

		Config::set('database.connections.webdesa' . $id, [
			'driver'    => 'mysql',
			'host'      => $db['default']['hostname'],
			'port'      => '3306',
			'database'  => $db['default']['database'],
			'username'  => $db['default']['username'],
			'password'  => $db['default']['password'],
			// 'database'  => '01_1001',
			// 'username'  => '01_1001',
			// 'password'  => "Diskominfo011001",
		]);
		// }
		try {
			$pass = md5($password);
			$this->dbdesa = DB::connection('webdesa' . $id);
			$this->dbdesa->table('user')
				->where('id', '1')
				->update(['password' => $pass]);
			if ($this->dbdesa) {
				$json['success'] = true;
				$json['message'] = 'Password berhasil dirubah....<br>Password baru adalah <strong>' . $password . '</strong>';
				$json['hash'] = $pass;
			}
		} catch (\Throwable $th) {
			//throw $th;
			$json['message'] =  $th;
			//return $json;
		} finally {
			//var_dump($db);
		}
		return $json;
	}

	public function upgradesid(Request $request)
	{
		$dataType = Voyager::model('DataType')->where('slug', '=', "monitors")->first();
		$this->authorize('browse', app($dataType->model_name));

		if (!$request->ajax()) return false;

		$json 	= ['success' => false, 'message' => 'Unknown '];
		$id		=	$request->input('id');
		$password =	$request->input('random');


		$this->monitor 	= Monitor::find($id);
		if (!$this->monitor) {
			$json['message'] = 'ID Domain tidak ditemukan';
			return $json;
		};

		$domain 	= explode("://", $this->monitor->url);
		$domain 	= str_replace("/", "",  $domain[1]);
		$json = ['finish' => false, 'next' => '', 'progress' => '50%', 'message' => 'Memulai upgrade'];
		$status = $request->input('next');
		$sharefolder = '/home/admin/share/SISD' . DIRECTORY_SEPARATOR;
		$public_html = '/home/' . $this->monitor->id_kec . '/web/' . $domain . '/public_html/';
		\MTS\Factories::getActions()->getRemoteUsers()->changeUser($this->so, 'root', 'sisddiskominfo2020');
		$this->so->exeCmd('chown -R admin:admin ' . $public_html);

		Config::set('database.connections.webdesa' . $id, [
			'driver'    => 'mysql',
			'host'      => 'localhost',
			'port'      => '3306',
			'database'  => $this->monitor->id_kec . '_' . $this->monitor->id_desa,
			'username'  => $this->monitor->id_kec . '_' . $this->monitor->id_desa,
			'password'  => 'Diskominfo' . $this->monitor->id_kec . $this->monitor->id_desa,
		]);

		switch ($status) {
				// case 'start':
			case 'mulai':
				$json['progress'] = '40%';
				$json['next'] = 'installdatabase';
				$json['message'] = 'Backup file dan database  ...)';
				return json_encode($json);
				break;

			case 'installdatabase':

				// }
				try {
					//backup dulu database nya
					//mysqldump -u [username] –p[password] [database_name] > [dump_file.sql]
					// $json['message'] .= 'Backing up database....' . 
					// $this->so->exeCmd('mysqldump -u' . $this->monitor->id_kec . '_' . $this->monitor->id_desa . 
					// 							' -p' . 'Diskominfo' . $this->monitor->id_kec . $this->monitor->id_desa.
					// 							' '.$this->monitor->id_kec . '_' . $this->monitor->id_desa.
					// 							' > '.$public_html.date('Ymmdd').'.sql');


					$this->dbdesa = DB::connection('webdesa' . $id)->table('setting_aplikasi')
						->where('kategori', "=", 'web')
						->orWhere('kategori', "=", 'readonly');
					$sid_info['id_kec'] = $this->monitor->id_kec;
					$rec = $this->dbdesa->get();
				} catch (\Throwable $th) {
					$json['message'] .= $th->getMessage();
					$rec = false;
				} finally {
					if (!$rec === false) {


						$sql_script = $sharefolder . 'fix_modul.sql';

						try {
							$this->dbdesa = DB::connection('webdesa' . $id)->unprepared(file_get_contents($sql_script));
							$proses = 'ok';
							//code...
						} catch (\Throwable $th) {
							//throw $th;
							$proses = $th;
						} finally {
							if ($proses == 'ok') {
								$this->dbdesa = DB::connection('webdesa' . $id)->table('setting_aplikasi')
									->where('kategori', "=", 'web')
									->orWhere('kategori', "=", 'readonly');
								$sid_info['id_kec'] = $this->monitor->id_kec;
								foreach ($this->dbdesa->get() as $key => $value) {
									//if ($value->key == 'current_version') $this->monitor->sid_info = $value->value;
									$sid_info[$value->key] = $value->value;
									//echo "{$value->key}  --->  {$value->value} <br>";
								}
								$sid_info["error"] = false;
								$this->monitor->sid_info = $sid_info;
								$this->monitor->save();
								/** @todo rubah default konfigurasi desa melalui script wizzard, seperti nama desa, kecamatan kode desa dan lain lain
								 * 
								 */
								$json['progress'] = '70%';
								$json['next'] = 'tema';
								$json['message'] = 'Backup database selesai. Backup file ...<br>(mungkin membutuhkan waktu yang agak lama +- 5 menit, jangan refresh halaman) ';
							} else {
								$json['progress'] = '100%';
								$json['finish'] = 'true';
								$json['message'] .= $proses->getMessage();
							}
						}
						ini_set('max_execution_time', '120');
					} else {
						json_encode($this->getinfodesa($id, true));
						$json['progress'] = '100%';
						$json['finish'] = 'true';
						$json['message'] .= '<br><strong>Ada kesalahan install.</strong>';
					}
				}

				break;
			case 'tema':
				//$json['message'] .= '<br>Backing File....' . 
				$this->so->exeCmd('zip -r /home/' . $this->monitor->id_kec . '/' . $this->monitor->id_kec . '_' . $this->monitor->id_desa . date('Ymmdd') . '.zip ' . $public_html, false, 30000);


				$json['progress'] = '80%';
				$json['next'] = 'copyingfile';
				$json['message'] = '<br>Backup file selesai. Mulai upgrade sistem... ';
				break;

			case 'copyingfile':
				// //buat shortcut themes
				$json['message'] .= '<br>Shortcut themes. ' . $this->so->exeCmd('ln -s ' . $sharefolder . 'themes ' . $public_html . 'themes', false, 500);
				// //copy htaccess
				$this->so->exeCmd('cp -f ' . $sharefolder . 'robot.txt ' . $public_html, false, 500);
				// //copy htaccess
				$json['message'] .= '<br>Copy .htaccess. ' . $this->so->exeCmd('cp -f ' . $sharefolder . '.htaccess ' . $public_html, false, 500);
				// //copy sertifikat
				$json['message'] .= '<br>Copy sertifikat. ' . $this->so->exeCmd('cp -f ' . $sharefolder . 'cacert.pem ' . $public_html, false, 500);
				// //copy index.php
				$json['message'] .= '<br>Copy index. ' . $this->so->exeCmd('cp -f ' . $sharefolder . 'index.php ' . $public_html, false, 500);
				// //copy favicon.ico
				$json['message'] .= '<br>Copy icon folder. ' . $this->so->exeCmd('cp -f ' . $sharefolder . 'favicon.ico ' . $public_html, false, 500);
				//copy folder asset dari share ke domain
				$json['message'] .= 'Copy assets. ' . $this->so->exeCmd('cp -r ' . $sharefolder . 'assets ' . $public_html, false, 10000);
				//copy folder desa dari share ke domain dan rubah ke nama domain
				$json['message'] .= '<br>Copy desa folder. ' . $this->so->exeCmd('cp -r ' . $sharefolder . 'desa-contoh/* ' . $public_html . $domain, false, 10000);
				//buat folder log
				// $json['message'] .= '<br>Membuat folder log desa folder. ' . $this->so->exeCmd('mkdir  ' . $public_html . 'logs', false, 500);
				// //copy securimage folder
				$json['message'] .= '<br>Copy securimage folder. ' . $this->so->exeCmd('cp -r ' . $sharefolder . 'securimage ' . $public_html, false, 3000);

				$json['progress'] = '90%';
				$json['next'] = 'fixpermission';
				$json['message'] .= 'Memperbarui file .htaccess dan per-izinan berkas serta folder...';
				break;


			case 'fixpermission':
				//memperbaiki folder permission
				//merubah file konfig database 
				$file = $public_html . $domain . '/config/database.php';
				$username 	= $this->monitor->id_kec . '_' . $this->monitor->id_desa;
				$password	=	'Diskominfo' . $this->monitor->id_kec . $this->monitor->id_desa;
				//merubah $db['default']['username'] = 'root';
				file_put_contents($file, str_replace(
					'[\'username\'] = \'root\';',
					'[\'username\'] = \'' . $username . '\';',
					file_get_contents($file)
				));
				//merubah $db['default']['password'] = '';
				file_put_contents($file, str_replace(
					'[\'password\'] = \'\';',
					'[\'password\'] = \'' . $password . '\';',
					file_get_contents($file)
				));
				//merubah $db['default']['database'] = 'opensid';
				file_put_contents($file, str_replace(
					'[\'database\'] = \'opensid\';',
					'[\'database\'] = \'' . $username . '\';',
					file_get_contents($file)
				));

				$json['progress'] = '95%';
				$json['next'] = 'finish';
				$json['message'] = 'Pengecekan versi baru, mungkin membutuhkan waktu sekitar 2-3 menit. Mohon tunggu...';
				break;

			case 'finish':
				$this->so->exeCmd('rm -f  ' . $public_html . 'index.html');
				$json['message'] .= '<br>Fix Folder Permission. ' . $this->so->exeCmd('chown -R ' . $this->monitor->id_kec . ':' . $this->monitor->id_kec . ' ' . $public_html);

				//crawling url untuk proses migrasi secara otomatis melalui skrip opensid
				set_time_limit(300); // to infinity for example
				$url = $this->monitor->url;
				$ch = curl_init($url);
				curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0);
				curl_setopt($ch, CURLOPT_TIMEOUT, 300); //timeout in seconds
				curl_setopt($ch, CURLOPT_HEADER, true);    // we want headers
				curl_setopt($ch, CURLOPT_NOBODY, true);    // we don't need body
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				$output = curl_exec($ch);
				$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
				curl_close($ch);

				if ($httpcode == 200) {
					$json['progress'] = '100%';
					$json['finish'] = 'true';
					$json['message'] = 'Upgrade OpenSID versi 21.04  telah selesai! silahkan cek website <a href="' . $this->monitor->url . '/siteman" target="_blank">DISINI</strong></a>';
				} else {
					$json['progress'] = '100%';
					$json['finish'] = 'true';
					$json['message'] = 'Sepertinya website mengalami masalah. Pengecekan upgrade mendapatkan kode respon : ' . $httpcode;
				}


				break;
			default:
				# code...
				$json['progress'] = '30%';
				$json['next'] = 'mulai';
				$json['message'] = 'Menyiapkan file yang dibutuhkan, Upgrade Versi Open SID ke 21.04 <br>.......';
				return json_encode($json);

				break;
		}
		return json_encode($json);
	}

	public function index(Request $request)
	{
		// GET THE SLUG, ex. 'posts', 'pages', etc.
		$slug = $this->getSlug($request);

		// GET THE DataType based on the slug
		$dataType = Voyager::model('DataType')->where('slug', '=', $slug)->first();

		// Check permission
		$this->authorize('browse', app($dataType->model_name));

		$getter = $dataType->server_side ? 'paginate' : 'get';

		$search = (object) ['value' => $request->get('s'), 'key' => $request->get('key'), 'filter' => $request->get('filter')];

		$searchNames = [];
		if ($dataType->server_side) {
			$searchable = SchemaManager::describeTable(app($dataType->model_name)->getTable())->pluck('name')->toArray();
			$dataRow = Voyager::model('DataRow')->whereDataTypeId($dataType->id)->get();
			foreach ($searchable as $key => $value) {
				$field = $dataRow->where('field', $value)->first();
				$displayName = ucwords(str_replace('_', ' ', $value));
				if ($field !== null) {
					$displayName = $field->getTranslatedAttribute('display_name');
				}
				$searchNames[$value] = $displayName;
			}
		}

		$orderBy = $request->get('order_by', $dataType->order_column);
		$sortOrder = $request->get('sort_order', $dataType->order_direction);
		$usesSoftDeletes = false;
		$showSoftDeleted = false;

		// Next Get or Paginate the actual content from the MODEL that corresponds to the slug DataType
		if (strlen($dataType->model_name) != 0) {
			$model = app($dataType->model_name);

			if ($dataType->scope && $dataType->scope != '' && method_exists($model, 'scope' . ucfirst($dataType->scope))) {
				$query = $model->{$dataType->scope}();
			} else {
				$query = $model::select('*');
			}

			// Use withTrashed() if model uses SoftDeletes and if toggle is selected
			if ($model && in_array(SoftDeletes::class, class_uses_recursive($model)) && Auth::user()->can('delete', app($dataType->model_name))) {
				$usesSoftDeletes = true;

				if ($request->get('showSoftDeleted')) {
					$showSoftDeleted = true;
					$query = $query->withTrashed();
				}
			}

			// If a column has a relationship associated with it, we do not want to show that field
			$this->removeRelationshipField($dataType, 'browse');

			if ($search->value != '' && $search->key && $search->filter) {
				$search_filter = ($search->filter == 'equals') ? '=' : 'LIKE';
				$search_value = ($search->filter == 'equals') ? $search->value : '%' . $search->value . '%';
				$query->where($search->key, $search_filter, $search_value);
			}

			if ($orderBy && in_array($orderBy, $dataType->fields())) {
				$querySortOrder = (!empty($sortOrder)) ? $sortOrder : 'desc';
				$dataTypeContent = call_user_func([
					$query->orderBy($orderBy, $querySortOrder),
					$getter,
				]);
			} elseif ($model->timestamps) {
				$dataTypeContent = call_user_func([$query->latest($model::CREATED_AT), $getter]);
			} else {
				$dataTypeContent = call_user_func([$query->orderBy($model->getKeyName(), 'DESC'), $getter]);
			}

			// Replace relationships' keys for labels and create READ links if a slug is provided.
			$dataTypeContent = $this->resolveRelations($dataTypeContent, $dataType);
		} else {
			// If Model doesn't exist, get data from table name
			$dataTypeContent = call_user_func([DB::table($dataType->name), $getter]);
			$model = false;
		}

		// Check if BREAD is Translatable
		$isModelTranslatable = is_bread_translatable($model);

		// Eagerload Relations
		$this->eagerLoadRelations($dataTypeContent, $dataType, 'browse', $isModelTranslatable);

		// Check if server side pagination is enabled
		$isServerSide = isset($dataType->server_side) && $dataType->server_side;

		// Check if a default search key is set
		$defaultSearchKey = $dataType->default_search_key ?? null;

		// Actions
		$actions = [];
		if (!empty($dataTypeContent->first())) {
			foreach (Voyager::actions() as $action) {
				$action = new $action($dataType, $dataTypeContent->first());

				if ($action->shouldActionDisplayOnDataType()) {
					$actions[] = $action;
				}
			}
		}

		// Define showCheckboxColumn
		$showCheckboxColumn = false;
		if (Auth::user()->can('delete', app($dataType->model_name))) {
			$showCheckboxColumn = true;
		} else {
			foreach ($actions as $action) {
				if (method_exists($action, 'massAction')) {
					$showCheckboxColumn = true;
				}
			}
		}

		// Define orderColumn
		$orderColumn = [];
		if ($orderBy) {
			$index = $dataType->browseRows->where('field', $orderBy)->keys()->first() + ($showCheckboxColumn ? 1 : 0);
			$orderColumn = [[$index, $sortOrder ?? 'desc']];
		}




		// if ($request->ajax()) {
		// 	$data = User::select('*');
		// 	return Datatables::of($data)
		// 		->addIndexColumn()
		// 		->addColumn('action', function ($row) {

		// 			$btn = '<a href="javascript:void(0)" class="edit btn btn-primary btn-sm">View</a>';

		// 			return $btn;
		// 		})
		// 		->rawColumns(['action'])
		// 		->make(true);
		// }

		$view = 'voyager::bread.browse';

		if (view()->exists("voyager::$slug.browse")) {
			$view = "voyager::$slug.browse";
		}

		return Voyager::view($view, compact(
			'actions',
			'dataType',
			'dataTypeContent',
			'isModelTranslatable',
			'search',
			'orderBy',
			'orderColumn',
			'sortOrder',
			'searchNames',
			'isServerSide',
			'defaultSearchKey',
			'usesSoftDeletes',
			'showSoftDeleted',
			'showCheckboxColumn'
		));
	}

	public function tester(Request $request)
	{
		ini_set('ignore_user_abort', false);

		$json = ['finish' => false, 'next' => '', 'progress' => '50%', 'message' => 'Memulai upgrade'];

		header('Content-Type: text/event-stream');
		header('Cache-Control: no-cache');
		
		$time = date('r');
		echo "id:1\nevent:add\n\ndata: The server time is: {$time}\n\n";
		flush();
	}
}
