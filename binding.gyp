{
	'targets': [
		{
			'include_dirs': [
				"<!(node -e \"require('nan')\")"
			],
			'target_name': 'processUtils',
			'sources': [ 'ProcessUtils.cc' ]
		}
	]
}