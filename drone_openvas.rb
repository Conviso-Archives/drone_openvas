#!/usr/bin/ruby
require 'rubygems'
require 'yaml'
require 'fileutils'
require 'zip/zip'

PATH = File.dirname(__FILE__)
LIB_PATH = File.join(File.dirname(__FILE__), 'lib')
DEBUG = false
CONFIG_FILE = File.join(PATH, 'config.yml')

require File.join(LIB_PATH, 'parse/sax/openvas')
require File.join(LIB_PATH, 'parse/dom/openvas')
require File.join(LIB_PATH, 'parse/writer/conviso')
require File.join(LIB_PATH, 'communication/xmpp')
require File.join(LIB_PATH, 'output/debug')

if !File.exists?(CONFIG_FILE)
  puts('Configuration file is missing.')
  exit
end

configuration = YAML.load_file(CONFIG_FILE)

debug = Output::Debug.new(configuration)
Output::Debug::level = configuration['debug_level'].to_i || 0

debug.info('Intializing Openvas Drone ...')

analysis_modules = []
Dir.glob(File.join(LIB_PATH, 'analysis/*_analysis.rb')).each do |a| 
  debug.info("Loading analysis module:  [#{a}]")
  begin 
    require a
    a =~ /analysis\/(\w+)_analysis.rb/
    am = eval("Analysis::#{$1.capitalize}.new()")
    am.config = configuration['analysis'][$1.downcase]
    am.debug = debug
    analysis_modules << am
  rescue Exception => e
    debug.error("Error loading analysis module:  [#{a}]")
  end
end




module Drone
  class Openvas
    def initialize(config = '', debug = nil, analyses = [])
      @analyses = analyses
      @config = config
      @debug = debug
      @comm = Communication::XMPP.new(@config, @debug)
      __validate_configuration
    end
    
    def run
      if @comm.active?
        @config['sources'].each do |s|
	        xml_files = __scan_input_directory(s)

	        xml_files.each do |xml_file|
            begin
	            openvas_structure = __parse_file(xml_file)
            rescue Exception => e
              @debug.error("Error parsing XML file: [#{xml_file}]")
              next
            end

	          if __sent_structure(openvas_structure,s)
             compressed_file = __compress_file(xml_file)
              __archive_file(compressed_file) unless @config['archive_directory'].to_s.empty?
	          end
	        end
        end
      end
    end
    
    
    private
    def __sent_structure(openvas_structure, source)
      @analyses.select {|a| a.class.superclass == Analysis::Interface::Bulk}.each {|a| openvas_structure[:issues] = a._analyse(openvas_structure[:issues])}

      response = openvas_structure[:issues].collect do |issue|
        @analyses.select {|a| !a.class.superclass == Analysis::Interface::Individual}.each {|a| issue = a._analyse(issue)}

        issue[:duration] = openvas_structure[:duration]

        source['tool_name'] = @config['tool_name']
        ret = @comm.send_msg(Parse::Writer::Conviso.build_xml(issue, source))
        sleep 2

        if @config['xmpp']['importer_address'] =~ /validator/
          sleep 2
          msg = @comm.receive_msg
          ret = false
          if msg =~ /[OK]/
            @debug.info('VALIDATOR - THIS MESSAGE IS VALID')
          else
            @debug.info('VALIDATOR - THIS MESSAGE IS INVALID')
          end
        end
        
        ret
       end 

       response = response + [true]            

       response.inject{|a,b| a & b}
    end
    
    def __validate_configuration
      @config['sources'].each do |s|
        if !File.exists?(s['input_directory'].to_s)
	        @debug.error("Input directory #{s['input_directory']}does not exist.")
	        exit
        end
      end
      if !@config['archive_directory'].nil? && !File.exists?(@config['archive_directory'].to_s)
	      @debug.error('Archive directory does not exist.')
	      exit
      end
    end
    
    def __scan_input_directory(source)
      @debug.info("Pooling input directory ...")
      files = Dir.glob(File.join(source['input_directory'], '*.xml'))
      @debug.info("##{files.size} files were found.")
      return files
    end

    def __parse_file (xml_file = '')
      @debug.info("Parsing xml file [#{xml_file}].")
      arachni_parse = Parse::SAX::Openvas.new()
      arachni_parse.parse_file(xml_file)
    end
    
    def __archive_file (zip_file = '')
      @debug.info("Archiving xml file [#{zip_file}].")
      FileUtils.mv(zip_file, @config['archive_directory'])
    end
    
    def __compress_file (xml_file = '')
      @debug.info("Compressing xml file [#{xml_file}].")
      zip_file_name = xml_file + ".zip"
      File.unlink(zip_file_name) if File.exists?(zip_file_name)
      zip = Zip::ZipFile.new(zip_file_name, true)
      zip.add(File.basename(xml_file), xml_file)
      zip.close
      File.unlink(xml_file)
      return zip_file_name
    end
    
  end
end

drone = Drone::Openvas.new(configuration, debug ,analysis_modules)
drone.run
