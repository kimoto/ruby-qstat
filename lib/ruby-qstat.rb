#-*- coding: utf-8 -*-
require 'open3'
require 'nokogiri'
require 'active_support'
require 'kconv'
require 'logger'

class String
  def force_convert_to(from, to=nil)
    if to.nil?
      to = from
    end
    self.encode!("UTF-16BE", from, :invalid => :replace, :undef => :replace, :replace => '?')
    self.encode!(to)
  end
end

class QStat
  DEFAULT_MAX_PING = 50

  @@qstat_path = "qstat"
  @@logger = Logger.new(nil)

  class Response
    attr_accessor :address
    attr_accessor :xml
    attr_accessor :doc
    attr_accessor :gametype
    attr_accessor :gamename

    def status_code
      server = @doc.search("/qstat/server[1]").first
      if server.attributes["type"].value.upcase == @gametype.upcase
        if server.attributes["address"].value == @address
          return server.attributes["status"].value
        end
      end
      nil
    end

    def valid?
      case status_code
      when "UP"
        true
      else
        false
      end
    end

    def to_s
      @xml
    end

    def to_ror
      Hash.from_xml(@doc.to_s)
    end
  end

  class ServerInfo
    attr_accessor :addr
    attr_accessor :num_players
    attr_accessor :map
    attr_accessor :response
    attr_accessor :time
    attr_accessor :server_name
    attr_accessor :players
    attr_accessor :game_type

    attr_accessor :ping
    attr_accessor :retries
    attr_accessor :number_of_max_players
    attr_accessor :number_of_players
    attr_accessor :status

    attr_accessor :rules

    class Rule
      attr_accessor :protocol
      attr_accessor :gamedir
      attr_accessor :gamename
      attr_accessor :bots
      attr_accessor :dedicated
      attr_accessor :sv_os
      attr_accessor :secure
      attr_accessor :version
      attr_accessor :game_port
      attr_accessor :game_tag

      def initialize
      end

      def self.create_from_xml(doc)
        rule = Rule.new
        rule.protocol = doc.search("rule[name=protocol]").text
        rule.gamedir = doc.search("rule[name=gamedir]").text
        rule.gamename = doc.search("rule[name=gamename]").text
        rule.bots = doc.search("rule[name=bots]").text
        rule.dedicated = doc.search("rule[name=dedicated]").text
        rule.sv_os = doc.search("rule[name=sv_os]").text
        rule.secure = doc.search("rule[name=secure]").text
        rule.version = doc.search("rule[name=version]").text
        rule.game_port = doc.search("rule[name=game_port]").text
        rule.game_tag = doc.search("rule[name=game_tag]").text
        rule
      end

      def game_tags
        if @game_tag =~ /^.*\n@(.*)$/
          $1.split(",")
        else
          []
        end
      end
    end

    def initialize(data=nil)
      if data
        parse_qstat_query_player(data)
      end
    end

    def self.create_from_xml(doc)
      info = self.new
      info.addr = doc.search("/server/hostname").text
      info.server_name = doc.search("/server/name").text
      info.game_type = doc.search("/server/gametype").text
      info.map = doc.search("/server/map").text
      info.num_players = doc.search("/server/numplayers").text
      info.number_of_max_players = doc.search("/server/maxplayers").text
      info.ping = doc.search("/server/ping").text
      info.retries = doc.search("/server/retries").text
      info.rules = []
      doc.search("/server/rules").each{ |rule|
        info.rules << Rule.create_from_xml(rule)
      }
      info.players = []
      doc.search("/server/players/player").each{ |player|
        info.players << PlayerInfo.create_from_xml(player)
      }
      info.number_of_players = [info.players.size, info.number_of_max_players].join(" / ")
      info.status = doc.search("/server").first.attributes["status"].value
      info
    end

    def parse_qstat_query_player(data)
      lines = data.split(/\n/)
      @header = lines[0]
      @body = lines[1..-1]
      @players = []
      @rules = []

      if no_response? or down?
        return nil
      end

      if @header =~ /^(\d+(?:.\d+){3}:\d+)\s+(\d+\/\d+)\s+(\d+\/\d+)\s+(.*?)\s+([\d\s]+\/\s+\d+)\s+\S+\s+(.*)$/
        @addr = $1
        @num_players = $2
        @map = $4
        @response = $5
        @server_name = $6

        if @body
          if @body.first =~ /^\t\s*\d+\s*frags.*$/
            @body.each{ |player_info_line|
              @players << PlayerInfo.new(player_info_line)
            }
          else
            server_info = @body.join("\n")
            server_info.force_convert_to('UTF-8')
            server_info.sub!(/^\s+/, "")
            server_info.gsub!(/\u0001/, "")
            hash = {}
            ary = server_info.split(",").map{|e| e.split("=")}
            ary.each{ |e|
              hash[e.first] = e.last
            }
            rule = Rule.new
            rule.protocol = hash["protocol"]
            rule.gamedir = hash["gamedir"]
            rule.gamename = hash["gamename"]
            rule.bots = hash["bots"]
            rule.dedicated = hash["dedicated"]
            rule.sv_os = hash["sv_os"]
            rule.secure = hash["secure"]
            rule.version = hash["version"]
            rule.game_port = hash["game_port"]
            rule.game_tag = hash["game_tag"]
            p rule.game_tags
            @rules << rule
          end
        end
      end

      @ping = parse_map_info.first
      @number_of_max_players = parse_number_of_players.last
      @number_of_players = [number_of_active_players, @number_of_max_players].join(" / ")
    end

    def number_of_active_players
      @players.size
    end

    def no_response?
      @header =~ /^(\d+(?:.\d+){3}:\d+)\s+no response$/
    end

    def down?
      @header =~ /^(\d+(?:.\d+){3}:\d+)\s+DOWN$/
    end

    def playing_time
      if empty_server?
        return "00:00"
      end
      longest_playing_player.time_to_s
    end

    def playing_time_seconds
      if empty_server?
        return 0
      end
      longest_playing_player.time_to_i
    end

    def longest_playing_player
      @players.max_by{ |player|
        player.time_to_i
      }
    end

    def empty_server?
      @players.empty?
    end

    def suggest_game_type
      unless @game_type.nil?
        return @game_type
      end

      if (not @rules.empty?) and (not @rules.first.game_tags.empty?)
        return @rules.first.game_tags.first
      end

      return 'unknown'
    end

    private
    def parse_number_of_players
      @num_players.gsub(" ", "").split("/")
    end

    def parse_map_info
      @response.gsub(" ", "").split("/")
    end
  end

  class PlayerInfo
    attr_accessor :name
    attr_accessor :frags
    attr_accessor :time

    def initialize(player_info_line=nil)
      if player_info_line.nil?
        return self
      end

      if player_info_line =~ /^\s+(\S+)\s+(\S+)\s+(.*?s)\s+(.*)$/
        @frags = $1
        @time = $3
        @name = $4
        self
      else
        raise "not found playerinfo structure: #{player_info_line}"
      end
    end

    def self.create_from_xml(xml)
      player_info = self.new
      player_info.name = xml.search("./name").text
      player_info.time = xml.search("./time").text
      player_info.frags = xml.search("./frags").text
      player_info
    end

    def time_to_i
      qstat_timestr_to_seconds(@time)
    end

    def time_to_s
      (minutes, seconds) = time_to_i.divmod(60)
      (hours, minutes) = minutes.divmod(60)
      "%02d:%02d" % [hours, minutes]
    end

    def to_s
      "#<#{@name} #{time_to_s}>"
    end

    private
    def qstat_timestr_to_seconds(timestr)
      if timestr =~ /^\s*(\d+)h\s*(\d+)m\s*(\d+)s\s*$/
        hours = $1.to_i
        min = $2.to_i
        sec = $3.to_i
      elsif timestr =~ /^\s*(\d+)m\s*(\d+)s\s*$/
        hours = 0
        min = $1.to_i
        sec = $2.to_i
      elsif timestr =~ /^\s*(\d+)s\s*$/
        hours = min = 0
        sec = $1.to_i
      elsif timestr =~ /^\s*(\d+)\s*$/
        hours = min = 0
        sec = $1.to_i
      end
      (hours * 60 * 60) + (min * 60) + sec
    end
  end

  def initialize
    raise "not implemented"
  end

  def self.qstat_path=(path)
    @@qstat_path = path
  end

  def self.logger=(logger)
    @@logger = logger
  end

  def self.query(host, gametype) # query player info
    self.exec_qstat_query_cmd "#{@@qstat_path} -P -utf8 -nh -#{gametype} #{host}"
  end
  def self.server_info(*args)
    self.query(*args)
  end

  def self.query_serverinfo(host, gametype) # query server info
    self.exec_qstat_query_cmd "#{@@qstat_path} -R -utf8 -nh -#{gametype} #{host}"
  end

  def self.query_serverlist(host, gametype, gamename, maxping=DEFAULT_MAX_PING)
    self.qslist(host, gametype, gamename, maxping){ |response|
      if response.valid?
        servers = response.doc.search("/qstat/server").to_a
        if servers.size <= 1
          raise "broken response" # 1件以下はおかしいっす
        end

        # 最初のserverは構造情報なので除去
        servers.shift

        # からじゃないよね??
        if servers.empty?
          raise "broken response#2"
        end

        # 取得したすべてのサーバー情報に対して
        # ServerInfo化していく
        infos = []
        servers.each{ |server|
          info = ServerInfo.create_from_xml(Nokogiri(server.to_s))
          infos << info
        }
        infos
      else
        raise "response is invalid: #{response.inspect}"
      end
    }
  end

  def self.read_from_xml(path)
    doc = Nokogiri(File.read(path))
    servers = doc.search("/qstat/server").to_a
    if servers.size <= 1
      raise "broken response" # 1件以下はおかしいっす
    end

    # 最初のserverは構造情報なので除去
    servers.shift

    # からじゃないよね??
    if servers.empty?
      raise "broken response#2"
    end

    # 取得したすべてのサーバー情報に対して
    # ServerInfo化していく
    infos = []
    servers.each{ |server|
      info = ServerInfo.create_from_xml(Nokogiri(server.to_s))
      infos << info
    }
    infos
  end

  def self.qslist(host, gametype, gamename, maxping=DEFAULT_MAX_PING, &block)
    res = Response.new
    res.address = host
    res.gametype = gametype
    res.gamename = gamename

    broken_xml = self.get_xml(host, gametype, gamename){ |line|
      if line =~ /<ping>(\d+)<\/ping>/
        ping = Regexp.last_match(1).to_i 
        if maxping < ping
          true
        end
      end
    }

    doc = Nokogiri(broken_xml)
    doc.search("/qstat/server/ping").each{ |ping_tag|
      if ping_tag.text.to_i >= maxping
        ping_tag.parent.remove
      end
    }
    res.doc = doc
    res.xml = doc.to_s

    if block_given?
      block.call(res)
    else
      res
    end
  end
  def self.qstat(*args, &block)
    self.qslist(*args, &block)
  end

  ## Low API
  def self.exec_qstat_query_cmd(cmd_str)
    ServerInfo.new self.exec_cmd(cmd_str).force_convert_to("UTF-8")
  end

  def self.exec_cmd(*params, &filter)
    data = ""
    Open3.popen3(*params){ |i,o,e,w|
      i.close_write

      tl = Thread.new{
        begin
          while line = o.gets 
            if block_given? and filter.call(line)
              data += line
              Process.kill :TERM, w.pid
              break
            end
            data += line
          end
        rescue
          @@logger.error $!
        end
      }
      tl2 = Thread.new{
        begin
          while !e.eof?
            @@logger.info e.read 1024
          end
        rescue
          @@logger.error $!
        end
      }
      tl.join
    }
    data
  end

  def self.get_xml(host, gametype, gamename, &filter)
    self.exec_cmd("#{@@qstat_path} -utf8 -xml -P -R -nh -#{gametype},game=#{gamename} #{host}", &filter)
  end
end
