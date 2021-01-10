package cn.tla001.spring.demo.plugin;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.filter.AbstractFilter;
import org.apache.logging.log4j.message.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Plugin(name = "LogAlarmFilter", category = "Core", elementType = "filter", printObject = true)
public class LogAlarmFilter extends AbstractFilter {
    private static final Logger logger = LoggerFactory.getLogger(LogAlarmFilter.class);

    private static Set<String> logFilterItems = Sets.newConcurrentHashSet();
    private static String regExStr = "";
    private static Pattern pattern = Pattern.compile(regExStr);

    public LogAlarmFilter() {
        super(Result.NEUTRAL, Result.NEUTRAL);
    }

    private Result filter(Level level, String msg){
        if (level == null || msg == null){
            return Result.NEUTRAL;
        }
        if ("ERROR".equalsIgnoreCase(level.toString())){
            Matcher matcher = pattern.matcher(msg);
            if (matcher.find()){
                return Result.DENY;
            }else {
                //如果不处理，一定要返回NEUTRAL，否则会影响其他Filter的执行
                return Result.NEUTRAL;
            }
        }
        return Result.NEUTRAL;
    }

    @PluginFactory
    public static LogAlarmFilter createFilter(){
        return new LogAlarmFilter();
    }

    private static synchronized void compileFilterItems(){
        regExStr = Joiner.on("|").join(logFilterItems);
        pattern = Pattern.compile(regExStr);
        logger.info("Update regExStr:[{}]", regExStr);
    }

    public static Boolean delFilterItem(String item){
        if (StringUtils.isBlank(item)){
            return Boolean.FALSE;
        }
        if (!logFilterItems.contains(item)){
            return Boolean.TRUE;
        }
        logFilterItems.remove(item);
        compileFilterItems();
        return Boolean.TRUE;
    }

    public static Boolean addFilterItem(String item){
        if (StringUtils.isBlank(item)){
            return Boolean.FALSE;
        }
        if (logFilterItems.contains(item)){
            return Boolean.TRUE;
        }
        logFilterItems.add(item);
        compileFilterItems();
        return Boolean.TRUE;
    }

    @Override
    public Result filter(LogEvent event) {
        return filter(event.getLevel(), event.getMessage().getFormattedMessage());
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, Message msg, Throwable t) {
        return filter(level, msg.getFormattedMessage());
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, Object msg, Throwable t) {
        return filter(level, msg.toString());
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object... params) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2, Object p3) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2, Object p3, Object p4) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2, Object p3, Object p4, Object p5) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2, Object p3, Object p4, Object p5, Object p6) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2, Object p3, Object p4, Object p5, Object p6, Object p7) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2, Object p3, Object p4, Object p5, Object p6, Object p7, Object p8) {
        return filter(level, msg);
    }

    @Override
    public Result filter(org.apache.logging.log4j.core.Logger logger, Level level, Marker marker, String msg, Object p0, Object p1, Object p2, Object p3, Object p4, Object p5, Object p6, Object p7, Object p8, Object p9) {
        return filter(level, msg);
    }


}
