#!/usr/bin/env php
<?php
/**
 * Convert a CSV file exported from LastPass into an XML file that can me imported into KeePass or MacPass.
 */

$options = [
    'i:' => 'input-file:',
    'o:' => 'output-file:'
];

$option_values = getopt(implode('', array_keys($options)), $options);
$input_file = 'php://stdin';
$output_file = 'php://stdout';
$timestamp = date('Y-m-d\Th:i:s\Z');
$database_name = 'LastPass';
$num_records = 0;

foreach ($option_values as $opt => $value) {
    switch ($opt) {
        case 'i':
        case 'input-file':
            $input_file = $value;
            $database_name = basename($value);
            break;

        case 'o':
        case 'output-file':
            $output_file = $value;
            break;

        default:
            break;
    }
}

$fd_in = fopen($input_file, 'r');
if (! $fd_in) {
    exit('Could not open input file ' . $input_file);
}

$fd_out = fopen($output_file, 'w');
if (! $fd_out) {
    exit('Could not open output file ' . $output_file);
}

$header = array_flip(array_map('strtolower', fgetcsv($fd_in)));

$group_records = [];
while ($line = fgetcsv($fd_in)) {
    $num_records++;
    $group = $line[$header['grouping']];
    if (empty($group) || $group == '(none)') {
        $group = 'General';
    }

    // Convert to key names that KeePass expects and convert html entities. urlencode does not work here.
    $group_records[$group][] = [
        'URL' => htmlentities($line[$header['url']]),
        'UserName' => htmlentities($line[$header['username']]),
        'Password' => htmlentities($line[$header['password']]),
        'Notes' => htmlentities($line[$header['extra']]),
        'Title' => htmlentities($line[$header['name']])
    ];
}
fclose($fd_in);

// File XML header

$str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<KeePassFile>
  <Meta>
    <Generator>lastpasscsv2keepassxml</Generator>
    <DatabaseName>$database_name</DatabaseName>
    <DatabaseNameChanged>$timestamp</DatabaseNameChanged>
    <DatabaseDescription/>
    <DatabaseDescriptionChanged>$timestamp</DatabaseDescriptionChanged>
    <DefaultUserName/>
    <DefaultUserNameChanged>$timestamp</DefaultUserNameChanged>
    <MaintenanceHistoryDays>365</MaintenanceHistoryDays>
    <Color/>
    <MasterKeyChanged/>
    <MasterKeyChangeRec>-1</MasterKeyChangeRec>
    <MasterKeyChangeForce>-1</MasterKeyChangeForce>
    <MemoryProtection>
      <ProtectTitle>False</ProtectTitle>
      <ProtectUserName>False</ProtectUserName>
      <ProtectPassword>True</ProtectPassword>
      <ProtectURL>False</ProtectURL>
      <ProtectNotes>False</ProtectNotes>
    </MemoryProtection>
    <RecycleBinEnabled>False</RecycleBinEnabled>
    <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
    <RecycleBinChanged>$timestamp</RecycleBinChanged>
    <EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
    <EntryTemplatesGroupChanged>$timestamp</EntryTemplatesGroupChanged>
    <HistoryMaxItems>10</HistoryMaxItems>
    <HistoryMaxSize>6291456</HistoryMaxSize>
    <LastSelectedGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastSelectedGroup>
    <LastTopVisibleGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleGroup>
    <Binaries/>
    <CustomData/>
  </Meta>
  <Root>
  ";


// The General group encapsulates other groups and contains entries that have no group

$str .= group_xml_header('General', $timestamp);

foreach ($group_records['General'] as $record) {
    $str .= xml_entry($record, $timestamp);
}

// Add other groups

foreach ($group_records as $group => $record_list) {
    if ($key == 'General') {
        continue;
    }
    $str .= group_xml_entry($group, $record_list, $timestamp);
}

$str .= "</Group>
<DeletedObjects/>
</Root>
</KeePassFile>
";

fwrite($fd_out, $str);
fclose($fd_out);

print 'Converted ' . $num_records . ' records.' . PHP_EOL;
exit(0);

/**
 * Generate a single XML entry.
 *
 * @param array $record Key/value pairs including name, url, username, password, and notes.
 * @param string $timestamp Time the entry was created
 *
 * @return string The XML for this entry.
 */

function xml_entry(array $record, string $timestamp): string
{
    $str = "<Entry>
    <UUID>" . uniqid() . "</UUID>
    <IconID>0</IconID>
    <ForegroundColor/>
    <BackgroundColor/>
    <OverrideURL/>
    ";

    $str .= (!isset($record['__TAGS__']) ? '<Tags/>' : '<Tags>' . $record['__TAGS__'] . '</Tags>') . PHP_EOL;

    $str .= "<Times>
    <LastModificationTime>$timestamp</LastModificationTime>
    <CreationTime>$timestamp</CreationTime>
    <LastAccessTime>$timestamp</LastAccessTime>
    <ExpiryTime>4001-01-01T00:00:00Z</ExpiryTime>
    <Expires>False</Expires>
    <UsageCount>0</UsageCount>
    <LocationChanged>$timestamp</LocationChanged>
    </Times>
    ";

    foreach ($record as $key => $value) {
        if ($key == '__TAGS__' || empty($value)) {
            continue;
        }
        $str .= '<String><Key>' . $key . '</Key>';
        $str .= ($key == 'Password' ? '<Value ProtectInMemory="True">' : '<Value>')  . $value . '</Value>';
        $str .= '</String>' . PHP_EOL;
    }

    $str .= "<AutoType>
    <Enabled>True</Enabled>
    <DataTransferObfuscation>0</DataTransferObfuscation>
    </AutoType>
    <History/>
    </Entry>
    ";

    return $str;
}

/**
 * Generate the header for an XML group. This does not include the closing </Group> tag.
 *
 * @param string $name Group name.
 * @param string $timestamp Time the entry was created
 *
 * @return string The XML for this entry.
 */

function group_xml_header(string $name, string $timestamp): string
{
    $str = "<Group>
    <UUID>" . uniqid() . "</UUID>
    <Name>$name</Name>
    <Notes/>
    <IconID>48</IconID>
      <Times>
      <LastModificationTime>$timestamp</LastModificationTime>
      <CreationTime>$timestamp</CreationTime>
      <LastAccessTime>$timestamp</LastAccessTime>
      <ExpiryTime>4001-01-01T00:00:00Z</ExpiryTime>
      <Expires>False</Expires>
      <UsageCount>0</UsageCount>
      <LocationChanged>$timestamp</LocationChanged>
    </Times>
    <IsExpanded>True</IsExpanded>
    <DefaultAutoTypeSequence/>
    <EnableAutoType>null</EnableAutoType>
    <EnableSearching>null</EnableSearching>
    <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
    ";

    return $str;
}

/**
 * Generate a complete XML group.
 *
 * @param string $name Group name.
 * @param array $records The records for this group.
 * @param string $timestamp Time the entry was created
 *
 * @return string The XML for this entry.
 */

function group_xml_entry(string $name, array $records, string $timestamp): string
{
    $str = group_xml_header($name, $timestamp);

    foreach ($records as $record) {
        $str .= xml_entry($record, $timestamp);
    }

    $str .= '</Group>';

    return $str;
}
