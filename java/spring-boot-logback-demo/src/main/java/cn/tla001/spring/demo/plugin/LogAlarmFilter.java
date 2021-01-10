package cn.tla001.spring.demo.plugin;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;
import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogAlarmFilter extends Filter<ILoggingEvent> {
    private static final Logger logger = LoggerFactory.getLogger(LogAlarmFilter.class);

    private static Set<String> logFilterItems = Sets.newConcurrentHashSet();
    private static String regExStr = "";
    private static Pattern pattern = Pattern.compile(regExStr);

    private FilterReply filter(Level level, String msg){
        if (level == null || msg == null){
            return FilterReply.NEUTRAL;
        }
        if ("ERROR".equalsIgnoreCase(level.toString())){
            Matcher matcher = pattern.matcher(msg);
            if (matcher.find()){
                return FilterReply.DENY;
            }else {
                //如果不处理，一定要返回NEUTRAL，否则会影响其他Filter的执行
                return FilterReply.NEUTRAL;
            }
        }
        return FilterReply.NEUTRAL;
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
    public FilterReply decide(ILoggingEvent iLoggingEvent) {
        return filter(iLoggingEvent.getLevel(), iLoggingEvent.getFormattedMessage());
    }
}
