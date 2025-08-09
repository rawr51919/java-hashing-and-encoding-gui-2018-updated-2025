package fr.cryptohash;

public class WhirlpoolTables {
    public final long[] table0;
    public final long[] table1;
    public final long[] table2;
    public final long[] table3;
    public final long[] table4;
    public final long[] table5;
    public final long[] table6;
    public final long[] table7;

	@SuppressWarnings("squid:S107")
	public WhirlpoolTables(long[] table0, long[] table1, long[] table2, long[] table3,
                  long[] table4, long[] table5, long[] table6, long[] table7) {
        this.table0 = table0;
        this.table1 = table1;
        this.table2 = table2;
        this.table3 = table3;
        this.table4 = table4;
        this.table5 = table5;
        this.table6 = table6;
        this.table7 = table7;
    }
}
