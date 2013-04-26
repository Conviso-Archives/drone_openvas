require '../lib/parse/dom/openvas'

parse = Parse::DOM::Openvas.new
xml_files = Dir.glob('./sample/*.xml')

total_time_start = Time.now.tv_sec
xml_files.each do |f|
  puts "Parsing file #{f} ..."

  t_start = Time.now.tv_sec
  struct = parse.parse_file(f)
  t_stop = Time.now.tv_sec

  puts "Was found [#{struct[:results].size}] results"
  puts "This file has [#{File.size(f)/1000.0}] KB"
  puts "The parser toke [#{t_stop - t_start}] seconds"
  puts "\n\n"
  puts struct.inspect
end

total_time_stop = Time.now.tv_sec
puts "\n"
puts "* Total time was: [#{total_time_stop - total_time_start}] seconds"

